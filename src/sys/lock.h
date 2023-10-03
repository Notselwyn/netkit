#ifndef SYS__LOCK_H
#define SYS__LOCK_H

void netkit_workers_decr(void);
void netkit_workers_incr(void);
void netkit_workers_wait(void);
void netkit_workers_init(void);

#endif