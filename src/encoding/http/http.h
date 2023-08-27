#ifndef ENCODING__HTTP_HTTP_H
#define ENCODING__HTTP_HTTP_H

#include <linux/types.h>

int enc_http_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index);

#endif