#ifndef PIPELINE__XOR__XOR_H
#define PIPELINE__XOR__XOR_H

#include <linux/types.h>

int layer_xor_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index);

#endif