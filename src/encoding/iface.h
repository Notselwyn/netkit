#ifndef ENCODING__IFACE_H
#define ENCODING__IFACE_H

#include <linux/types.h>

int enc_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);


//const int (**ENC_FUNCTIONS)(u8 index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);


struct enc_list_entry {
    struct list_head list;
    int (*func)(const struct enc_list_entry*, const u8*, size_t, u8**, size_t*);
};

#endif
