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
    const int (*COMM_HANDLERS[])(const packet_req_t*, packet_res_t**, size_t*) = {
        cmd_handle_exec
    };

    pr_err("[*] processing cmd (cmd_id: %d)\n", req_packet->cmd_id);
    
    *res_buf = kzmalloc(sizeof(packet_res_t), GFP_KERNEL);
    *res_buflen = sizeof(packet_res_t); // leaves 1 byte buffer

    if (req_packet->cmd_id < 0 || req_packet->cmd_id >= sizeof(COMM_HANDLERS) / sizeof(COMM_HANDLERS[0]))
    {
        (*res_buf)->status = -EDOM;
        goto LAB_OUT;
    }

    // this should be nicer
    (*res_buf)->status = COMM_HANDLERS[req_packet->cmd_id](req_packet, res_buf, res_buflen);

LAB_OUT:
    pr_err("[*] res_buf->status: %d\n", (*res_buf)->status);
    return (*res_buf)->status;
}