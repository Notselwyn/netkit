#ifndef CORE__CMD__HANDLERS_H
#define CORE__CMD__HANDLERS_H

#include "../packet/packet.h"

int cmd_handle_exec(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen);

#endif