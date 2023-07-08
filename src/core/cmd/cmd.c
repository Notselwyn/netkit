#include <linux/types.h>

#include "cmd.h"

#include "handlers.h"
#include "../packet/packet.h"

/**
 * Handles the request (based on command id etc)
 */
int cmd_process(const packet_t *packet, u8 **res_buf, size_t *res_buflen)
{
    const int (*COMM_HANDLERS[])(const packet_t*, u8**, size_t*) = {
        cmd_handle_exec
    };

    pr_err("[*] processing cmd (cmd_id: %d)\n", packet->cmd_id);

    if (packet->cmd_id < 0 || packet->cmd_id >= sizeof(COMM_HANDLERS) / sizeof(COMM_HANDLERS[0]))
        return -EDOM;

    // handler should set buffer in case of error to NULL
    return COMM_HANDLERS[packet->cmd_id](packet, res_buf, res_buflen);
}