#ifndef IO__INT_IFACE_H
#define IO__INT_IFACE_H

#include <linux/types.h>

#include "../mem/dynarr.h"

struct io_ops {
    int (*init)(void);
    int (*exit)(void);
};

int io_init(void);
int io_exit(void);
int io_process(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif