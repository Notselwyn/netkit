#include <linux/types.h>
#include <linux/slab.h>

#include "xor.h"

#include "../iface.h"
#include "../../netkit.h"
#include "../../sys/crypto.h"
#include "../../sys/mem.h"
#include "../../sys/debug.h"

static int _do_xor(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    // works with req_buflen == 0
    xor_crypt_diff_size(req_buf, req_buflen, CONFIG_PIPELINE_XOR_KEY, sizeof(CONFIG_PIPELINE_XOR_KEY), req_buf);

    *res_buf = req_buf;
    *res_buflen = req_buflen;

    return 0;
}

static int layer_xor_decode(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    return _do_xor(req_buf, req_buflen, res_buf, res_buflen);
}

static int layer_xor_encode(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    return _do_xor(req_buf, req_buflen, res_buf, res_buflen);
}

const struct pipeline_ops LAYER_XOR_OPS = {
    .decode = layer_xor_decode,
    .encode = layer_xor_encode,
    .handle_err = NULL
};

