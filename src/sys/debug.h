#ifndef SYS__DEBUG_H
#define SYS__DEBUG_H

#include <linux/module.h>
#include <linux/moduleparam.h>

#include "../netkit.h"

#if CONFIG_NETKIT_DEBUG
#define NETKIT_LOG(fmt, ...) pr_err(fmt, ##__VA_ARGS__)
#else
#define NETKIT_LOG(fmt, ...) {}
#endif

#endif