#ifndef SYS__FILE_H
#define SYS__FILE_H

#include <linux/types.h>

int file_read(const char* filename, u8 **out_buf, size_t *out_buflen);

#endif