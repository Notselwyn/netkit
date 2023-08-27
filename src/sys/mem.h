#ifndef SYS__MEM_H
#define SYS__MEM_H

#include <linux/string.h>
#include <linux/slab.h>

void *_do_kzmalloc(size_t size, int flags);
void _do_kzfree(void* buf, size_t size);
void *kzrealloc(void* buf_old, size_t size_old, size_t size_new);

static inline void *kzmalloc(size_t size, int flags)
{
    if (unlikely(size == 0))
        return ERR_PTR(-EINVAL);

    return _do_kzmalloc(size, flags);
}

static inline void kzfree(void* buf, size_t size)
{
    if (unlikely(size != 0))
        _do_kzfree(buf, size);
}

#endif