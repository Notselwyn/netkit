#ifndef IO__IFACE_H
#define IO__IFACE_H

#include <linux/types.h>

struct io_ops {
    int (*init)(void);
    int (*exit)(void);
};

int io_init(void);
int io_exit(void);
int io_process(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif