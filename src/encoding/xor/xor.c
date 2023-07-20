#include <linux/types.h>
#include <linux/slab.h>

#include "xor.h"

#include "../iface.h"
#include "../../mem/mngt.h"

#define XOR_KEY 0x41

static int enc_xor_do(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    *res_buflen = req_buflen;
    *res_buf = kzmalloc(*res_buflen, GFP_KERNEL);

    pr_err("[*] doing xor...\n");
    if (IS_ERR(*res_buf))
    {
        *res_buf = NULL;
        *res_buflen = 0;

        return PTR_ERR(*res_buf);
    }

    for (int i=0; i < *res_buflen; i++)
        (*res_buf)[i] = req_buf[i] ^ XOR_KEY;

    return 0;
}

int enc_xor_process(u8 index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    u8* next_req_buf = NULL;
    size_t next_req_buflen = 0;
    u8* next_res_buf = NULL;
    size_t next_res_buflen = 0;
    int retv;

    pr_err("[*] processing xor (req_buflen: %lx)...\n", req_buflen);
    retv = enc_xor_do(req_buf, req_buflen, &next_req_buf, &next_req_buflen);
    if (retv < 0)
    {
        pr_err("[!] xor 1 failed\n");
 
        return retv;
    }

    pr_err("[*] executing next func...\n");
    
    CALL_NEXT_ENCODING(index+1, next_req_buf, next_req_buflen, &next_res_buf, &next_res_buflen);

    // reset next_req_buf{len}
    kzfree(next_req_buf, next_req_buflen);
    next_req_buf = NULL;
    next_req_buflen = 0;

    pr_err("[*] executing xor...\n");

    // execute encode() even if next->func() errors to wrap it in a response
    if (next_res_buf)
    {
        enc_xor_do(next_res_buf, next_res_buflen, res_buf, res_buflen);
        kzfree(next_res_buf, next_res_buflen);
        next_res_buf = NULL;
        next_res_buflen = 0;
    }

    if (retv < 0)
    {
        pr_err("[!] xor 2 failed\n");
        return retv;
    }

    return 0;
}