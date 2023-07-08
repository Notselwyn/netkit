#ifndef IO__SERVER__SERVER_H
#define IO__SERVER__SERVER_H

#include "../iface.h"

//int server_init(void);
//int server_exit(void);
//int server_conn_destroy(struct kref *ref);

#define MAX_SERVER_PACKET_SIZE 8096

extern const struct io_ops IO_SERVER_OPS;

typedef struct server_packet {
    struct socket *client_sk;
    u8 *req_buf;
    size_t req_buflen;
} server_packet_t;

#endif