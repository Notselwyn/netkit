#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/sched.h>
#include <linux/kref.h>


// wait for all conns to finish
static struct kref workers_ref;
DECLARE_WAIT_QUEUE_HEAD(workers_wait_queue);

void netkit_workers_decr(void)
{
    // kref_sub without release()
    atomic_sub(1, (atomic_t *)&workers_ref.refcount);
    wake_up(&workers_wait_queue);
}

void netkit_workers_incr(void)
{
    kref_get(&workers_ref);
}

void netkit_workers_wait(void)
{
    wait_event(workers_wait_queue, kref_read(&workers_ref) == 1);
}

void netkit_workers_init(void)
{
    kref_init(&workers_ref);
}