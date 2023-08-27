#include <linux/types.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>

#include "socket.h"

#include "mem.h"
#include "debug.h"

__be32 inet_addr(const char *str)
{
    int a, b, c, d;
    char buf[4];

    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
    buf[0] = a; buf[1] = b; buf[2] = c; buf[3] = d;

    return *(__be32*)buf;
} 

int socket_create(__be32 ip, __be16 port, struct socket **out_sk, struct sockaddr_in **out_addr)
{
    int err = 0;

    NETKIT_LOG("[*] creating socket for ip: 0x%08x, port: 0x%04x\n", ip, port);

	err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, out_sk);
    if (err != 0) {
        NETKIT_LOG("[!] failed to create socket: %d\n", err);
        return err;
    }

    *out_addr = kzmalloc(sizeof(**out_addr), GFP_KERNEL);
    if (IS_ERR(*out_addr))
    {
        sock_release(*out_sk);
        *out_sk = NULL;
        err = PTR_ERR(*out_addr);
        *out_addr = NULL;

        return err;
    }

    (*out_addr)->sin_family = AF_INET;
    (*out_addr)->sin_addr.s_addr = ip;
    (*out_addr)->sin_port = port;

    return 0;
}

inline int socket_connect(struct socket *sk, struct sockaddr_in *addr)
{
    NETKIT_LOG("[*] attempting to connect to proxy...\n");
    return kernel_connect(sk, (struct sockaddr*)addr, sizeof(*addr), 0);
}

int socket_listen(struct socket *sk, struct sockaddr_in *addr)
{
    int retv;

    retv = kernel_bind(sk, (struct sockaddr *)addr, sizeof(*addr));
    kzfree(addr, sizeof(*addr));
    if (retv < 0) 
    {
        NETKIT_LOG("[!] failed to bind socket: %d\n", retv);
        goto LAB_OUT;
    }

    retv = sk->ops->listen(sk, 10);
    if (retv < 0)
    {
        NETKIT_LOG("[!] failed to listen on socket (err: %d)\n", retv);
        goto LAB_OUT;
    }

LAB_OUT:
    return retv;
}

int socket_read(struct socket *sk, u8 **out_buf, size_t *out_buflen)
{
	struct msghdr msg;
	struct kvec vec;
    size_t count;
    u8 *tmp_buf;
    const size_t TMP_BUFLEN = 4096;
    int retv; 

    tmp_buf = kzmalloc(TMP_BUFLEN, GFP_KERNEL);
    if (IS_ERR(tmp_buf))
        return PTR_ERR(tmp_buf);

    memset(&msg, '\x00', sizeof(msg));
    vec.iov_base = tmp_buf;
    vec.iov_len = TMP_BUFLEN;

    count = kernel_recvmsg(sk, &msg, &vec, 1, TMP_BUFLEN, 0);
    NETKIT_LOG("[*] read %lu bytes from socket\n", count);
    if (count < 0)
    {
        retv = count;
        goto LAB_ERR;
    }

    *out_buf = kzmalloc(count, GFP_KERNEL);
    if (IS_ERR(*out_buf))
    {
        *out_buf = NULL;
        retv = PTR_ERR(*out_buf);
        goto LAB_ERR;
    }

    *out_buflen = count;

    // count <= tmp_buflen always
    memcpy(*out_buf, tmp_buf, *out_buflen);

LAB_ERR:
    kzfree(tmp_buf, TMP_BUFLEN);

    return retv;
}

int socket_write(struct socket *sk, u8 *content, size_t content_len)
{
	struct msghdr msg;
	struct kvec vec = {
        .iov_base = content,
        .iov_len = content_len
    };
    int count;

    memset(&msg, '\x00', sizeof(msg));

    count = kernel_sendmsg(sk, &msg, &vec, 1, content_len);
    NETKIT_LOG("[+] wrote %u bytes to socket\n", count);

    return count;
}

int socket_proxy(__be32 ip, __be16 port, u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen)
{
    static struct socket *sock;
    struct sockaddr_in *addr;
    int retv = 0;

    retv = socket_create(ip, port, &sock, &addr);
    if (retv < 0)
        goto LAB_OUT_NO_SOCK;
    
    retv = socket_connect(sock, addr);
    if (retv < 0)
        goto LAB_OUT;
    
    retv = socket_write(sock, in_buf, in_buflen);
    if (retv < 0)
        goto LAB_OUT;

    retv = socket_read(sock, out_buf, out_buflen);
    if (retv < 0)
        goto LAB_OUT;

LAB_OUT:
    sock_release(sock);
    kzfree(addr, sizeof(*addr));
LAB_OUT_NO_SOCK:
    return retv;
}