#ifndef SYS__SOCKET_H
#define SYS__SOCKET_H

#include <linux/types.h>
#include <linux/inet.h>
#include <linux/net.h>

__be32 inet_addr(const char *str);
int socket_create(__be32 ip, __be16 port_htons, struct socket **sk_out, struct sockaddr_in **addr_out);
int socket_connect(struct socket *sk, struct sockaddr_in *addr);
int socket_listen(struct socket *sk, struct sockaddr_in *addr);
int socket_read(struct socket *sk, u8 **res_buf, size_t *res_buflen);
int socket_write(struct socket *sk, const u8 *content, size_t content_len);
int socket_proxy(__be32 ip, __be16 port, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen);

#endif