#ifndef IO__IFACE_H
#define IO__IFACE_H

#include <linux/types.h>

#include "../sys/debug.h"
#include "../pipeline/iface.h"

int io_init(void);
int io_exit(void);

/**
 * initial function after receiving data
 * prevents IO children (i.e. server/device) from calling pipeline_process() out of nowhere for clarity
 */ 
static inline int io_process(const struct pipeline_ops **pipeline_ops_arr, u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    NETKIT_LOG("[*] starting io transformation pipeline...\n");
    return pipeline_process(pipeline_ops_arr, req_buf, req_buflen, res_buf, res_buflen);
}

#endif