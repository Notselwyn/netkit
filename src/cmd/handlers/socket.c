#include <linux/types.h>

#include "socket.h"

#include "../../sys/socket.h"

int cmd_handle_proxy(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    if (req_buflen < 6)
        return -EMSGSIZE;

    return socket_proxy(*(__be32*)req_buf, *(__be16*)(req_buf+4), req_buf+6, req_buflen-6, res_buf, res_buflen);
}