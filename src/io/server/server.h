#ifndef IO__SERVER__SERVER_H
#define IO__SERVER__SERVER_H

#include "../iface.h"

int server_init(void);
int server_exit(void);

#define MAX_SERVER_PACKET_SIZE 8096

typedef struct server_packet {
    struct socket *client_sk;
    u8 *req_buf;
    size_t req_buflen;
} server_packet_t;

#endif