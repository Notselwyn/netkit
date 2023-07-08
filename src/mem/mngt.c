
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "mngt.h"

void *kzmalloc(size_t size, int flags)
{
    void *buf = kmalloc(size, flags);
    if (!buf)
        return ERR_PTR(-ENOMEM);

    memset(buf, '\x00', size);

    return buf;
}

void kzfree(void* var, size_t size)
{
    memset(var, '\x00', size);
    kfree(var);
}

void *kzrealloc(void* buf_old, size_t size_old, size_t size_new)
{
    void *buf_new = kzmalloc(size_new, GFP_KERNEL);
    if (IS_ERR(buf_new))
        return buf_new;

    if (buf_old == NULL)
        return buf_new;

    memcpy(buf_new, buf_old, size_old);
    kzfree(buf_old, size_old);

    return buf_new;
}