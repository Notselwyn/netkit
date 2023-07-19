#ifndef ENCODING__XOR__XOR_H
#define ENCODING__XOR__XOR_H

#include <linux/types.h>

//int enc_xor_process(const struct enc_list_entry *next_entry, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);
int enc_xor_process(u8 index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif