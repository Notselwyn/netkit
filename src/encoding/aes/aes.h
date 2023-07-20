#ifndef ENCODING__AES__AES_H
#define ENCODING__AES__AES_H

#include <linux/types.h>

#include "../iface.h"

int enc_aes_process(u8 index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif