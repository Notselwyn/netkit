#ifndef ENCODING__AES__AES_H
#define ENCODING__AES__AES_H

#include <linux/types.h>

int enc_aes_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index);

#include "../iface.h"

#endif