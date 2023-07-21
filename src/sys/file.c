#include <linux/types.h>
#include <linux/slab.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/umh.h>

#include "../sys/mem.h"

int file_read(const char* filename, u8 **out_buf, size_t *out_buflen)
{
    struct file *file;
    char *tmp_buf;
    int retv = 0;

    pr_err("[*] going to open file\n");
    file = filp_open(filename, O_RDONLY | (force_o_largefile() ? O_LARGEFILE : 0), 0);
    if (IS_ERR(file))
    {
        pr_err("[!] failed to open file\n");
        return PTR_ERR(file);
    }

    pr_err("[*] going to read file (read_iter: %p, read: %p)\n", file->f_op->read_iter, file->f_op->read);

    tmp_buf = kzmalloc(4096, GFP_KERNEL);
    if (IS_ERR(tmp_buf))
    {
        retv = PTR_ERR(tmp_buf);
        goto LAB_OUT_NO_FILP;
    }

    pr_err("[*] reading file (%p, %p)...\n", file, tmp_buf);
    retv = kernel_read(file, tmp_buf, 4096, NULL);
    if (retv < 0)
    {
        pr_err("[!] failed to read file\n");
        goto LAB_OUT;
    }

    *out_buflen = retv;
    *out_buf = kzmalloc(retv, GFP_KERNEL);
    if (IS_ERR(*out_buf))
    {
        retv = PTR_ERR(*out_buf);
        *out_buf = NULL;
        *out_buflen = 0;

        goto LAB_OUT;
    }

    memcpy(*out_buf, tmp_buf, *out_buflen);

    while (retv == 4096)
    {
        pr_err("[*] reading file...\n");
        retv = kernel_read(file, tmp_buf, 4096, NULL);
    
        kzrealloc(*out_buf, *out_buflen, *out_buflen + retv);
        memcpy(*out_buf + *out_buflen, tmp_buf, retv);
        *out_buflen += retv;
        
        if (retv < 0)
        {
            pr_err("[!] failed to read file\n");
            goto LAB_OUT;
        }
    }

LAB_OUT:
    filp_close(file, NULL);
LAB_OUT_NO_FILP:
    kzfree(tmp_buf, 4096);

    if (retv >= 0)
        return 0;

    return retv;
}

int file_write(const char *filename, const u8 *content, size_t content_len)
{
    struct file *file;
    int retv;

    file = filp_open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0);
    if (IS_ERR(file))
    {
        pr_err("[!] failed to open file\n");
        return PTR_ERR(file);
    }

    pr_err("[*] writing size: %ld\n", content_len);
    retv = kernel_write(file, content, content_len, 0);
    filp_close(file, NULL);
    if (retv < 0)
    {
        pr_err("[!] failed to write to file\n");
        return retv;
    }
    
    return retv;
}

int file_exec(const char *path, char **argv, char **envp)
{
    return call_usermodehelper(path, argv, envp, UMH_WAIT_PROC);
}