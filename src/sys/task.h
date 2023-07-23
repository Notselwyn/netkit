#ifndef SYS__TASK_H
#define SYS__TASK_H

#include <linux/types.h>

int kthread_stop_by_name(const char *name);
int module_stop(void* data);

#endif