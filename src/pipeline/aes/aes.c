#include <linux/types.h>
#include <linux/slab.h>

#include "aes.h"

#include "../iface.h"
#include "../../sys/crypto.h"
#include "../../sys/debug.h"
#include "../../sys/mem.h"

#define AES_KEY "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"

static int layer_aes_decode(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    int retv;

    retv = aes256cbc_decrypt(AES_KEY, 32, req_buf, req_buflen, res_buf, res_buflen);
    kzfree(req_buf, req_buflen);

    if (retv < 0)
        return retv;

    return 0;
}

static int layer_aes_encode(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    int retv;

    if (req_buflen == 0)
    {
        *res_buf = req_buf;
        *res_buflen = req_buflen;

        return 0;
    }
    
    retv = aes256cbc_encrypt(AES_KEY, 32, req_buf, req_buflen, res_buf, res_buflen);
    kzfree(req_buf, req_buflen);

    if (retv < 0)
        return retv;

    return 0;
}

const struct pipeline_ops LAYER_AES_OPS = {
    .decode = layer_aes_decode, 
    .encode = layer_aes_encode, 
    .handle_err = NULL
};
