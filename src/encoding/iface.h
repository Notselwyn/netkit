#ifndef ENCODING__IFACE_H
#define ENCODING__IFACE_H

#include <linux/types.h>
#include <linux/kallsyms.h>

#include "../sys/debug.h"

int enc_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);
int call_next_encoding(size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif
