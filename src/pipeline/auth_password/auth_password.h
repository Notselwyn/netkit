#ifndef PIPELINE__AUTH_PASSWORD__AUTH_PASSWORD_H
#define PIPELINE__AUTH_PASSWORD__AUTH_PASSWORD_H

#include <linux/types.h>

#define CORRECT_HASH "\x5e\x88\x48\x98\xda\x28\x04\x71\x51\xd0\xe5\x6f\x8d\xc6\x29\x27\x73\x60\x3d\x0d\x6a\xab\xbd\xd6\x2a\x11\xef\x72\x1d\x15\x42\xd8"

#define SHA256_DIGEST_SIZE 32
void sha256(const u8 *data, unsigned int len, u8 *out);

int layer_auth_password_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index);

#include "../iface.h"

#endif