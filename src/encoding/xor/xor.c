#include <linux/types.h>
#include <linux/slab.h>

#include "xor.h"

#include "../iface.h"
#include "../../sys/crypto.h"
#include "../../sys/mem.h"
#include "../../sys/debug.h"

#define XOR_KEY 0x41

int enc_xor_process(u8 index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    u8* next_req_buf = NULL;
    size_t next_req_buflen = 0;
    u8* next_res_buf = NULL;
    size_t next_res_buflen = 0;
    int retv;

    NETKIT_LOG("[*] processing xor (req_buflen: %lx)...\n", req_buflen);
    retv = xor_crypt(XOR_KEY, req_buf, req_buflen, &next_req_buf, &next_req_buflen);
    if (retv < 0)
    {
        NETKIT_LOG("[!] xor 1 failed\n");
 
        return retv;
    }

    NETKIT_LOG("[*] executing next func...\n");
    
    CALL_NEXT_ENCODING(index+1, next_req_buf, next_req_buflen, &next_res_buf, &next_res_buflen);

    // reset next_req_buf{len}
    kzfree(next_req_buf, next_req_buflen);
    next_req_buf = NULL;
    next_req_buflen = 0;

    NETKIT_LOG("[*] executing xor...\n");

    // execute encode() even if next->func() errors to wrap it in a response
    if (next_res_buf)
    {
        xor_crypt(XOR_KEY, next_res_buf, next_res_buflen, res_buf, res_buflen);
        kzfree(next_res_buf, next_res_buflen);
        next_res_buf = NULL;
        next_res_buflen = 0;
    }

    if (retv < 0)
    {
        NETKIT_LOG("[!] xor 2 failed\n");
        return retv;
    }

    return 0;
}