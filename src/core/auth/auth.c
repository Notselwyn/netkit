#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/device.h>

#include "auth.h"

#include "handlers.h"
#include "../packet/packet.h"

int auth_process(const packet_req_t *req_packet)
{
    const int (*AUTH_HANDLERS[])(const u8*, size_t) = {
        password_hash_match
    };

    pr_err("[*] doing auth... (auth_id: %u)\n", req_packet->auth_id);

    if (req_packet->auth_id < 0 || req_packet->auth_id >= sizeof(AUTH_HANDLERS) / sizeof(*AUTH_HANDLERS))
        return -EDOM;

    return AUTH_HANDLERS[req_packet->auth_id](req_packet->password, PASSWORD_LEN);
}