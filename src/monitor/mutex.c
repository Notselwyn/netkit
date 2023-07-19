#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/kthread.h>
#include <linux/errno.h>

#include "mutex.h"

static struct task_struct *get_task_by_name(const char *name)
{
    struct task_struct *task;

    // Find the task_struct of the "netkit-loop" thread
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