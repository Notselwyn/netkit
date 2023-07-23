#include <linux/printk.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>

#include "symbol.h"

#include "file.h"
#include "../sys/mem.h"

static void *sym_lookup_probes(const char* sym_name)
{
    struct kprobe kp = {
        .symbol_name = sym_name,
    };
    void *retv;

    retv = ERR_PTR(register_kprobe(&kp));
    if (retv < 0)
        return retv;

    pr_err("[*] kprobe lookup '%s': %px\n", sym_name, kp.addr);

    retv = (void*)kp.addr;
    unregister_kprobe(&kp);

    return retv;
}

typedef unsigned long (*_sym_type__kallsyms_lookup_name)(const char*);
static _sym_type__kallsyms_lookup_name _sym_addr__allsyms_lookup_name;

static _sym_type__kallsyms_lookup_name get_kallsyms_lookup_name(void)
{
    if (_sym_addr__allsyms_lookup_name)
        return _sym_addr__allsyms_lookup_name;
    
    _sym_addr__allsyms_lookup_name = (_sym_type__kallsyms_lookup_name)sym_lookup_probes("kallsyms_lookup_name");

    return _sym_addr__allsyms_lookup_name;
}

/*
 * get symbol using kallsyms (not using kprobe since it's loud)
 */
void *sym_lookup(const char* sym_name)
{
    _sym_type__kallsyms_lookup_name kallsyms_lookup_name; 
    void *ret;

    kallsyms_lookup_name = get_kallsyms_lookup_name();
    
    // eventually disable KASAN if it's acting stupid:
    //kasan_disable_current(); 
    ret = (void*)kallsyms_lookup_name(sym_name);
    //kasan_enable_current();

    return ret;
}