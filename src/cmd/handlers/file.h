#ifndef CMD__HANDLERS__FILE_H
#define CMD__HANDLERS__FILE_H

#include <linux/types.h>

int cmd_handle_file_read(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);
int cmd_handle_file_write(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);
int cmd_handle_file_exec(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif