#include <linux/types.h>
#include <linux/slab.h>

#include "aes.h"

#include "../iface.h"
#include "../../sys/crypto.h"
#include "../../sys/debug.h"
#include "../../sys/mem.h"

#define AES_KEY "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"

int layer_aes_process(pipeline_func_t *pipeline_funcs, size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    u8* next_req_buf = NULL;
    size_t next_req_buflen = 0;
    u8* next_res_buf = NULL;
    size_t next_res_buflen = 0;
    int retv;

    retv = aes256cbc_decrypt(AES_KEY, 32, req_buf, req_buflen, &next_req_buf, &next_req_buflen);
    if (retv < 0)
    {
        NETKIT_LOG("[!] aes 1 failed\n");
        return retv;
    }
    
    retv = call_next_layer(pipeline_funcs, index+1, next_req_buf, next_req_buflen, &next_res_buf, &next_res_buflen);
    kzfree(next_req_buf, next_req_buflen);

    // execute encode() even if next->func() errors to wrap it in a response
    if (next_res_buf == NULL)
        return retv;

    retv = aes256cbc_encrypt(AES_KEY, 32, next_res_buf, next_res_buflen, res_buf, res_buflen);
    if (retv < 0)
    {
        NETKIT_LOG("[!] aes 2 failed\n");
        return retv;
    }

    kzfree(next_res_buf, next_res_buflen);

    return 0;
}