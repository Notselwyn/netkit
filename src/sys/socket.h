#ifndef SYS__SOCKET_H
#define SYS__SOCKET_H

#include <linux/types.h>

__be32 inet_addr(const char *str);
int socket_create(__be32 ip, __be16 port_htons, struct socket **sk_out, struct sockaddr_in **addr_out);
int socket_connect(struct socket *sk, struct sockaddr_in *addr);
int socket_listen(struct socket *sk, struct sockaddr_in *addr);
int socket_read(struct socket *sk, u8 **res_buf, size_t *res_buflen);
int socket_write(struct socket *sk, u8 *req_buf, size_t req_buflen);
int socket_proxy(__be32 peer_ip, __be16 peer_port, u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen);

#endif