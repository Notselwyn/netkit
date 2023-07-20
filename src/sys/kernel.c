#include <linux/printk.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <net/netfilter/nf_conntrack_core.h>

#include "file.h"

void *sys_call_table = NULL;

void *get_sys_call_table(void)
{
    if (sys_call_table)
        return sys_call_table;

    return NULL;
}

static void *get_kallsyms_scan(void)
{
    // _printk:          ffffffff8116d120
    // sys_call_table:   ffffffff82a03060 
    // kallsyms_offsets: ffffffff8313c468
    // int 4, whereby: (cur >= 0 ? next > prev : prev > next) && kallsyms_offsets[0] == NULL
    void *kallsyms;
    //int *pos_current = (int*)&inet6_stream_ops;
    int *pos_current = &boot_cpu_data;
    //int *pos_current = (int*)dma_dummy_ops;
    size_t size = 0;
    int prev = 0;

    //nf_conntrack_l4proto_generic = NULL;
    // if sys_call_table was already scanned, then populate

    while (likely(!kthread_should_stop()))
    {
        if (unlikely(try_to_freeze()))
			continue;

        prev = *pos_current;
        pos_current += 4;
        if (likely(kallsyms == NULL))
        {
            if (unlikely(*pos_current == 0))
                kallsyms = (void*)pos_current;

            continue;
        }

        // if format of kallsyms:
        if ((*pos_current >= 0) ? (*pos_current > prev) : (prev > *pos_current))
        {
            size += 4;
        } else {
            if (size > 1024)
                pr_err("[+] stopped kallsyms chain at size_t %lu at ptr %px\n", size, kallsyms);
            kallsyms = NULL;
            size = 0;
        }

    }

    /*retv = file_read("/proc/kallsyms", &kallsyms_buf, &kallsyms_buflen);
    if (retv < 0)
    {
        pr_err("[!] failed to read /proc/kallsyms\n");
    }*/


    return NULL;
}

void *get_kallsyms(void)
{
    int ret;
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };

    ret = register_kprobe(&kp);
    if (ret < 0)
        return ret;
}