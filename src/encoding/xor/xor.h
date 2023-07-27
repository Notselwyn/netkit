#ifndef ENCODING__XOR__XOR_H
#define ENCODING__XOR__XOR_H

#include <linux/types.h>

int enc_xor_process(size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif