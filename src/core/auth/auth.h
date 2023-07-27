#ifndef CORE__AUTH__AUTH_H
#define CORE__AUTH__AUTH_H

#include "../packet/packet.h"

int auth_process(const struct packet_req *packet);

#endif