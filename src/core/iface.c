#include <linux/types.h>

#include "packet/packet.h"
#include "cmd/cmd.h"

int core_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    packet_req_t *packet;
    int retv;

    pr_err("[*] init packet with req_buflen: %lu\n", req_buflen);
    packet = packet_req_init((struct raw_packet_req*)req_buf, req_buflen);   
    if (IS_ERR(packet))
    {
        pr_err("[!] failed to init packet\n");
        return PTR_ERR(packet);
    }

    retv = cmd_process(packet, (packet_res_t**)res_buf, res_buflen);
    packet_destructor(packet);
    if (retv < 0)
    {
        pr_err("[!] failed to process command\n");

        return retv;
    }


    return 0;
}