#include <linux/types.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/kthread.h>
#include <linux/fcntl.h>
#include <linux/fs.h>

#include "task.h"

#include "symbol.h"

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

/*
 * direct copy
 */
static int try_release_module_ref(struct module *mod)
{
	int ret;

	/* Try to decrement refcnt which we set at loading */
	ret = atomic_sub_return(MODULE_REF_BASE, &mod->refcnt);
	BUG_ON(ret < 0);
	if (ret)
		/* Someone can put this right now, recover with checking */
		ret = atomic_add_unless(&mod->refcnt, MODULE_REF_BASE, 0);

	return ret;
}

/*
 * direct copy from kernel, but it's optimized away so no symbol :(
 */
static int try_stop_module(struct module *mod, int flags, int *forced)
{
	/* If it's not unused, quit unless we're forcing. */
	if (try_release_module_ref(mod) != 0) {
		*forced = (flags & O_TRUNC);
		if (!(*forced))
			return -EWOULDBLOCK;

		add_taint(TAINT_FORCED_RMMOD, LOCKDEP_NOW_UNRELIABLE);
	}

	/* Mark it as dying. */
	mod->state = MODULE_STATE_GOING;

	return 0;
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
	void (*free_module)(struct module*);
    int forced;
    int retv = 0;

    module_mutex = (struct mutex*)sym_lookup("module_mutex");
	if (mutex_lock_interruptible(module_mutex) != 0)
	{
        retv = -EINTR;
        goto LAB_OUT;
    }

    if (mod->state != MODULE_STATE_LIVE) {
		pr_err("%s already dying\n", mod->name);
		retv = -EBUSY;
		goto LAB_OUT;
	}

    // just relying on struct mod*
    retv = try_stop_module(mod, 0, &forced);
	if (retv != 0)
		goto LAB_OUT;

	mutex_unlock(module_mutex);

	pr_err("[*] exiting module...\n");
	mod->exit();
	
    // don't remove kernel live patches, since every module will be notified

	// sync RCU function calls
	pr_err("[*] syncing...\n");
	async_synchronize_full = (void (*)(void))sym_lookup("async_synchronize_full");
	async_synchronize_full();

	// pagefaults, so this does not return
	pr_err("[*] freeing...\n");
	free_module = (void (*)(struct module*))sym_lookup("free_module");
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