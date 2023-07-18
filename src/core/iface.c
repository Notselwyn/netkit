#include <linux/types.h>

#include "auth/auth.h"
#include "cmd/cmd.h"
#include "packet/packet.h"

#include "../mem/mngt.h"

int core_process(const u8 *req_buf, size_t req_buflen, packet_res_t **res_buf, size_t *res_buflen)
{
    packet_req_t *packet_req;
    u8* cmd_res_buf = NULL;
    size_t cmd_res_buflen = 0;
    u8 domain = STAT_DOM_CORE;
    int retv;

    pr_err("[*] init packet with req_buflen: %lu\n", req_buflen);
    packet_req = packet_req_init((struct raw_packet_req*)req_buf, req_buflen);   
    if (IS_ERR(packet_req))
    {
        pr_err("[!] failed to init packet\n");
        domain = STAT_DOM_PACKET;

        goto LAB_OUT;
    }
    
    retv = auth_process(packet_req);
    if (retv < 0)
    {
        pr_err("[!] failed to authenticate\n");
        domain = STAT_DOM_AUTH;

        goto LAB_OUT;
    }

    retv = cmd_process(packet_req, &cmd_res_buf, &cmd_res_buflen);
    packet_destructor(packet_req);
    if (retv < 0)
    {
        pr_err("[!] failed to process command\n");
        domain = STAT_DOM_CMD;

        kzfree(cmd_res_buf, cmd_res_buflen);

        goto LAB_OUT;
    }


LAB_OUT:
    *res_buf = kzmalloc(sizeof(packet_res_t) + cmd_res_buflen - 1, GFP_KERNEL);
    if (!*res_buf)
        return -ENOMEM;

    *res_buflen = sizeof(packet_res_t) + cmd_res_buflen;
    (*res_buf)->status.type = retv;
    (*res_buf)->status.domain = domain;

    if (cmd_res_buf)
    {
        memcpy((*res_buf)->content, cmd_res_buf, cmd_res_buflen);
        kzfree(cmd_res_buf, cmd_res_buflen);
    }

    pr_err("[*] res_buf->status: %d\n", (*res_buf)->status.type);
    return (*res_buf)->status.type;
}