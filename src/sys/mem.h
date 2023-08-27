#ifndef SYS__MEM_H
#define SYS__MEM_H

#include <linux/string.h>
#include <linux/slab.h>

void *kzmalloc(size_t size, int flags);
void kzfree(void* var, size_t size);
void *kzrealloc(void* buf_old, size_t size_old, size_t size_new);

#endif