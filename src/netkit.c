#include <linux/module.h>
#include <linux/kernel.h>

#include "netkit.h"
#include "device.h"
#include "server.h"

static int __init netkit_init(void)
{
    int retv = 0;

    pr_err("[+] module started\n");

    pr_err("[*] starting server...\n");
    retv = server_init();

    if (retv < 0)
        pr_err("[!] failed to start server (err: %d)\n", retv);

    return 0;
}

static void __exit netkit_exit(void)
{
    pr_err("[*] stopping module...\n");

    // let server run when netkit exits
    //server_exit();
    //device_exit();
}

module_init(netkit_init);
module_exit(netkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple hello world kernel module");
