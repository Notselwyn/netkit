#ifndef CMD__HANDLERS__SOCKET_H
#define CMD__HANDLERS__SOCKET_H

#include <linux/types.h>

int cmd_handle_proxy(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif