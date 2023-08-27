#ifndef IO__IFACE_H
#define IO__IFACE_H

#include <linux/types.h>

#include "../sys/debug.h"
#include "../encoding/iface.h"

int io_init(void);
int io_exit(void);

/**
 * initial function after receiving data
 * prevents IO children (i.e. server/device) from calling enc_process_start() out of nowhere for clarity
 */ 
static inline int io_process(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    NETKIT_LOG("[*] calling enc_process()...\n");
    return enc_process(req_buf, req_buflen, res_buf, res_buflen);
}

#endif