#include <linux/slab.h>
#include <linux/types.h>

#include "iface.h"

#include "xor/xor.h"
#include "aes/aes.h"

#include "../core/iface.h"
#include "../sys/mem.h"
#include "../sys/debug.h"

/**
 * function to get rid of the `struct enc_list_entry*` argument for the list
 */
static int enc_last_process(u8 index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    NETKIT_LOG("[*] doing core process...\n");
    return core_process(req_buf, req_buflen, res_buf, res_buflen);
}


const int (*ENC_FUNCTIONS[])(u8 index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen) = {
    enc_aes_process,
    enc_xor_process,
    enc_last_process
};

/**
 * heap guide (req):
 *  - caller allocates
 *  - caller free's
 * 
 * heap guide (res):
 *  - callee allocates
 *  - caller free's
 */
int enc_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    CALL_NEXT_ENCODING(0, req_buf, req_buflen, res_buf, res_buflen);

    NETKIT_LOG("[+] successfully returned from first_entry->func\n");

    return 0;
}
