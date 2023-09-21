#ifndef PIPELINE__HTTP__HTTP_H
#define PIPELINE__HTTP__HTTP_H

#include <linux/types.h>

#include "../../sys/mem.h"
#include "../iface.h"

int layer_http_process(pipeline_func_t *pipeline_funcs, size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);


#endif