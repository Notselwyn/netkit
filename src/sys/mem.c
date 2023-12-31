
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "mem.h"

void *_do_kzmalloc(size_t size, int flags)
{
    void *buf;

    buf = kcalloc(1, size, flags);
    if (buf == NULL)
        return ERR_PTR(-ENOMEM);

    return buf;
}

void _do_kzfree(void* buf, size_t size)
{
    memset(buf, '\x00', size);
    kfree(buf);
}

// don't do checks as macro, since kzrealloc will never be used with hardcoded values
void *kzrealloc(void* buf_old, size_t size_old, size_t size_new)
{
    void *buf_new;

    if (buf_old == NULL || size_old > size_new || size_new == 0) 
        return ERR_PTR(-EINVAL); 
    
    if (size_old == size_new) 
        return buf_old;

    // size is already validated
    buf_new = _do_kzmalloc(size_new, GFP_KERNEL);
    if (IS_ERR(buf_new))
        return buf_new;

    memcpy(buf_new, buf_old, size_old);

    // buf is already validated
    _do_kzfree(buf_old, size_old);

    return buf_new;
}