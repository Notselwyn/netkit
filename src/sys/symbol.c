#include <linux/printk.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/kprobes.h>

#include "symbol.h"

#include "file.h"
#include "../sys/mem.h"

static _sym_type__kallsyms_lookup_name _sym_addr__allsyms_lookup_name;

_sym_type__kallsyms_lookup_name get_kallsyms_lookup_name(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };
    const size_t SYM_NAME_LEN = strlen(kp.symbol_name)+1;
    char *func_name;
    void *retv;

    if (_sym_addr__allsyms_lookup_name)
        return _sym_addr__allsyms_lookup_name;

    retv = ERR_PTR(register_kprobe(&kp));
    if (retv < 0)
        return retv;

    func_name = kzmalloc(SYM_NAME_LEN, GFP_KERNEL);
    if (IS_ERR(func_name))
    {
        retv = func_name;
        goto LAB_OUT_NO_FUNC_NAME;
    }

    sprint_symbol(func_name, (unsigned long)kp.addr);
    //pr_err("[*] sprint_symbol: '%s', get_kallsyms: %px\n", func_name, kp.addr);

    _sym_addr__allsyms_lookup_name = (_sym_type__kallsyms_lookup_name)kp.addr;
    retv = _sym_addr__allsyms_lookup_name;

    kzfree(func_name, SYM_NAME_LEN);

LAB_OUT_NO_FUNC_NAME:
    unregister_kprobe(&kp);

    return retv;
}