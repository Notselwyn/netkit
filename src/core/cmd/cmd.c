#include <linux/types.h>

#include "cmd.h"

#include "handlers.h"
#include "../packet/packet.h"
#include "../../mem/mngt.h"

/**
 * Handles the request (based on command id etc)
 */
int cmd_process(const packet_req_t *req_packet, packet_res_t **res_buf, size_t *res_buflen)
{
    u8 *handler_res_buf = NULL;
    size_t handler_res_buflen = 0;
    int retv;

    const int (*COMM_HANDLERS[])(const packet_req_t*, u8**, size_t*) = {
        cmd_handle_exec
    };

    pr_err("[*] processing cmd (cmd_id: %d)\n", req_packet->cmd_id);

    if (req_packet->cmd_id < 0 || req_packet->cmd_id >= sizeof(COMM_HANDLERS) / sizeof(*COMM_HANDLERS))
    {
        *res_buf = kzmalloc(sizeof(packet_res_t), GFP_KERNEL);
        if (!*res_buf)
            return -ENOMEM;

        *res_buflen = sizeof(packet_res_t); // leaves 1 byte buffer
        (*res_buf)->status = -EDOM;
        goto LAB_OUT;
    }

    // this should be nicer
    retv = COMM_HANDLERS[req_packet->cmd_id](req_packet, &handler_res_buf, &handler_res_buflen);

    *res_buf = kzmalloc(sizeof(packet_res_t) + handler_res_buflen, GFP_KERNEL);
    if (!*res_buf)
        return -ENOMEM;

    *res_buflen = sizeof(packet_res_t) + handler_res_buflen;
    (*res_buf)->status = retv;

    if (handler_res_buf != NULL)
        memcpy(*res_buf, handler_res_buf, handler_res_buflen);

LAB_OUT:
    pr_err("[*] res_buf->status: %d\n", (*res_buf)->status);
    return (*res_buf)->status;
}