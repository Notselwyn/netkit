#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#include "stealth.h"

#include "../../netkit.h"
#include "../../sys/task.h"

int cmd_handle_exit(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    // run as kthread so underlaying layers can cleanup and round up the IO
    // conn-xyz --[spawn]--> netkit-exit --[call]--> netkit->exit() --[kill]--> {netkit-conn-loop, conn-xyz} 
    kthread_run(module_stop, THIS_MODULE, "netkit-exit");

    return 0;
}