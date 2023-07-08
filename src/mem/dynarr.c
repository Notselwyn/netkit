#ifndef MEM__DYNARR_C
#define MEM__DYNARR_C

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/slab.h>

#include "dynarr.h"
#include "mngt.h"


dynarr_t *dynarr_init(unsigned int typesize)
{
    dynarr_t *dnar;
   
    dnar = kzmalloc(sizeof(dnar), GFP_KERNEL);
    dnar->typesize = typesize;
    
    return dnar;
}


dynarr_t *dynarr_append(dynarr_t *dnar, const void *entry)
{
    size_t capacity_new;
    void *content_new;

    if (dnar->nmemb == dnar->capacity)
    {
        capacity_new = dnar->capacity ? dnar->capacity * 2 : 8;
        content_new = kzrealloc(dnar->content, dnar->capacity * dnar->typesize, capacity_new * dnar->typesize);
        if (IS_ERR(content_new))
            return content_new;

        dnar->content = content_new;
        dnar->capacity = capacity_new;
    }

    dnar->content[dnar->nmemb++] = entry;
    return dnar;
}

#endif