#ifndef MEM__MNGT_H
#define MEM__MNGT_H

#include <linux/string.h>

void *kzmalloc(size_t size, int flags);
void kzfree(void* var, size_t size);
void *kzrealloc(void* buf_old, size_t size_old, size_t size_new);


#endif