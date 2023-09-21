#ifndef PIPELINE__AUTH_PASSWORD__AUTH_PASSWORD_H
#define PIPELINE__AUTH_PASSWORD__AUTH_PASSWORD_H

#include <linux/types.h>

#include "../iface.h"

void sha256(const u8 *data, unsigned int len, u8 *out);

int layer_auth_password_process(pipeline_func_t *pipeline_funcs, size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif