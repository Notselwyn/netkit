#ifndef PIPELINE__XOR__XOR_H
#define PIPELINE__XOR__XOR_H

#include <linux/types.h>
#include "../iface.h"

int layer_xor_process(pipeline_func_t *pipeline_funcs, size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif