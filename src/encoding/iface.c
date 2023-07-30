#include <linux/slab.h>
#include <linux/types.h>

#include "iface.h"

#include "xor/xor.h"
#include "aes/aes.h"

#include "../core/iface.h"
#include "../sys/mem.h"
#include "../sys/debug.h"

static __inline int enc_last_process(size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    return core_process(req_buf, req_buflen, res_buf, res_buflen);
}

#if CONFIG_NETKIT_DEBUG
int call_next_encoding(size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    int (*ENC_FUNCTIONS[])(size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen) = {
        enc_aes_process,
        enc_xor_process,
        enc_last_process
    };

    char *sym_name;
    int retv;

    // for some reason symbol names are this big???
    sym_name = kzmalloc(1024, GFP_KERNEL);
    if (IS_ERR(sym_name))
        return PTR_ERR(sym_name);

    retv = sprint_symbol(sym_name, (unsigned long)ENC_FUNCTIONS[index]);
    if (retv < 0)
        return retv;

    NETKIT_LOG("[*] calling '%s' (req_buflen: %lu)\n", sym_name, req_buflen);
    retv = ENC_FUNCTIONS[index](index, req_buf, req_buflen, res_buf, res_buflen);
    NETKIT_LOG("[+] returned '%s' (res_buflen: %lu)\n", sym_name, *res_buflen);

    kzfree(sym_name, 1024);

    return retv;
}
#else 
__inline int call_next_encoding(size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    int (*ENC_FUNCTIONS[])(size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen) = {
        enc_aes_process,
        enc_xor_process,
        enc_last_process
    };

    return ENC_FUNCTIONS[index](index, req_buf, req_buflen, res_buf, res_buflen);
}
#endif

int __inline enc_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    call_next_encoding(0, req_buf, req_buflen, res_buf, res_buflen);

    return 0;
}
