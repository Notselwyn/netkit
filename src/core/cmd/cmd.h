#ifndef CORE__CMD__CMD_H
#define CORE__CMD__CMD_H

#include <linux/types.h>

#include "../packet/packet.h"

int cmd_process(const packet_req_t *req_packet, u8 **res_buf, size_t *res_buflen);

#endif