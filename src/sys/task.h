#ifndef SYS__TASK_H
#define SYS__TASK_H

#include <linux/types.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
    #define TASK_STATE(task) ((task)->__state)
#else
    #define TASK_STATE(task) ((task)->state)
#endif

int kthread_stop_by_name(const char *name);
int module_stop(void* data);

#endif