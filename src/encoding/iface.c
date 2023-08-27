#include <linux/slab.h>
#include <linux/types.h>

#include "iface.h"

#include "xor/xor.h"
#include "aes/aes.h"
#include "http/http.h"

#include "../sys/mem.h"
#include "../sys/debug.h"

/*int (*ENC_FUNCTIONS[])(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index) = {
    //enc_aes_process,
    //enc_xor_process,
    enc_http_process,
    enc_last_process
};*/