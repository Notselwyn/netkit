#ifndef SYS__FILE_H
#define SYS__FILE_H

#include <linux/types.h>

int file_read(const char *filename, u8 **out_buf, size_t *out_buflen);
int file_write(const char *filename, const u8 *content, size_t content_len);
int file_exec(const char *cmd, u8 **out_buf, size_t *out_buflen);

#endif