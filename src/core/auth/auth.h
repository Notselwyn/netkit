#ifndef CORE__AUTH__AUTH_H
#define CORE__AUTH__AUTH_H

#include "../packet/packet.h"

int auth_process(const packet_req_t *packet);

#endif