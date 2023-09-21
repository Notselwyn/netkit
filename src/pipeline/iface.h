#ifndef PIPELINE__IFACE_H
#define PIPELINE__IFACE_H

#include <linux/types.h>
#include <linux/kallsyms.h>

typedef int (pipeline_func_t)(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);
typedef int (pipeline_func_handle_err_t)(int retv, u8 **res_buf, size_t *res_buflen);

struct pipeline_ops {
    pipeline_func_t *decode;
    pipeline_func_t *encode;
    pipeline_func_handle_err_t *handle_err;
};

int pipeline_process(const struct pipeline_ops **pipeline_ops_arr, u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif
