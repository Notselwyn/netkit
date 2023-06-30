
#include <linux/string.h>
#include <linux/slab.h>

#include "mem.h"

void kzfree(void* var, size_t size)
{
    memset(var, '\x00', size);
    kfree(var);
}
