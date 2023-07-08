#ifndef COMMAND_IFACE_H
#define COMMAND_IFACE_H

#include <linux/types.h>

#include "../packet/packet.h"

int cmd_process(const packet_t *packet, u8 **res_buf, size_t *res_buflen);

#endif