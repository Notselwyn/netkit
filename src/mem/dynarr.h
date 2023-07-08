#ifndef MEM__DYNARR_H
#define MEM__DYNARR_H

#include <linux/types.h>

typedef struct dynarr_t {
    const void** content;
    size_t nmemb;
    size_t typesize;
    size_t capacity;
} dynarr_t;

// should only store pointers
dynarr_t* dynarr_init(unsigned int typesize);
dynarr_t* dynarr_append(dynarr_t* dnar, const void* entry);

#define DYNARR_INDEX(dnar, index, type) ((type)(((dynarr_t*)dnar)->content[index]))
#define DYNARR_LEN(dnar) (((dynarr_t*)dnar)->nmemb)

#endif