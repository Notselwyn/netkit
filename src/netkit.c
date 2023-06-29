#include <linux/module.h>
#include <linux/kernel.h>

#include "netkit.h"
#include "device.h"

static int __init netkit_init(void)
{
    int major = 0;

    pr_err("[+] module started\n");
    
    major = device_init();
    if (major < 0)
        return -1;

    return 0;
}

static void __exit netkit_exit(void)
{
    pr_err("[*] stopping module...\n");

    device_exit();
}

module_init(netkit_init);
module_exit(netkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple hello world kernel module");
