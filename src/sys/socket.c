#include <linux/types.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>

#include "../mem/mngt.h"

int socket_create(__be32 ip, short port_htons, struct socket **sk_out, struct sockaddr_in **addr_out)
{
    int err = 0;

	err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, sk_out);
    if (err != 0) {
        pr_err("[!] failed to create socket: %d\n", err);
        return err;
    }

    *addr_out = kzmalloc(sizeof(**addr_out), GFP_KERNEL);
    if (IS_ERR(*addr_out))
    {
        sock_release(*sk_out);
        *sk_out = NULL;
        err = PTR_ERR(*addr_out);
        *addr_out = NULL;

        return err;
    }

    (*addr_out)->sin_family = AF_INET;
    (*addr_out)->sin_addr.s_addr = ip;
    (*addr_out)->sin_port = port_htons;

    return 0;
}

int socket_connect(struct socket *sk, struct sockaddr_in *addr)
{
    return kernel_connect(sk, (struct sockaddr*)addr, sizeof(*addr), 0);
}

int socket_read(struct socket *sk, u8 **res_buf, size_t *res_buflen)
{
	struct msghdr msg;
	struct kvec vec;
    size_t count;
    u8 *tmp_buf = NULL;
    const size_t TMP_BUFLEN = 4096;
    int retv; 

    tmp_buf = kzmalloc(TMP_BUFLEN, GFP_KERNEL);
    if (IS_ERR(tmp_buf))
        return PTR_ERR(tmp_buf);

    pr_err("[*] tmp_buflen: %lu\n", TMP_BUFLEN);

    memset(&msg, '\x00', sizeof(msg));
    vec.iov_base = tmp_buf;
    vec.iov_len = TMP_BUFLEN;

    count = kernel_recvmsg(sk, &msg, &vec, 1, TMP_BUFLEN, 0);
    pr_err("[*] read %lu bytes\n", count);
    if (count < 0)
    {
        retv = count;
        goto LAB_ERR;
    }

    *res_buf = kzmalloc(count, GFP_KERNEL);
    if (IS_ERR(*res_buf))
    {
        *res_buf = NULL;
        retv = PTR_ERR(*res_buf);
        goto LAB_ERR;
    }

    *res_buflen = count;

    // count <= tmp_buflen always
    memcpy(*res_buf, tmp_buf, *res_buflen);

LAB_ERR:
    kzfree(tmp_buf, TMP_BUFLEN);

    return retv;
}

int socket_write(struct socket *sk, u8 *req_buf, size_t req_buflen)
{
	struct msghdr msg;
	struct kvec vec = {
        .iov_base = req_buf,
        .iov_len = req_buflen
    };
    int count;

    memset(&msg, '\x00', sizeof(msg));

    count = kernel_sendmsg(sk, &msg, &vec, 1, req_buflen);
    if (count < 0) {
        pr_err("[!] sock_recvmsg() failed (err: %d)\n", count);
    }

    return count;
}