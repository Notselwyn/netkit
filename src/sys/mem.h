#ifndef SYS__MEM_H
#define SYS__MEM_H

#include <linux/string.h>
#include <linux/slab.h>

void *kzrealloc(void* buf_old, size_t size_old, size_t size_new);

static inline __attribute__((always_inline)) void *kzmalloc(size_t size, long flags)
{
    void *retv;

    if (size == 0)
        return ERR_PTR(-EINVAL);
    
    retv = kcalloc(1, size, flags); 
    if (retv == NULL) 
        retv = ERR_PTR(-ENOMEM);

    return retv;
}

static inline __attribute__((always_inline)) void kzfree(void *buf, size_t size)
{
    if (size == 0 || buf == NULL)
        return;

    memset(buf, '\x00', size);
    kfree(buf);
}

#endif