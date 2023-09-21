#ifndef SYS__DEBUG_H
#define SYS__DEBUG_H

#include <linux/module.h>
#include <linux/moduleparam.h>

#include "../netkit.h"
#include "../sys/symbol.h"

#if CONFIG_NETKIT_DEBUG
#define NETKIT_LOG(fmt, ...) pr_err(fmt, ##__VA_ARGS__)
#else
#define NETKIT_LOG(fmt, ...)
#endif

#include "../sys/mem.h"

// pray that the compiler will optimize this when debug disabled
#define NETKIT_FUNC_CALL(func, ...) ({ \
    int retv; \
    char *sym_buf; \
    size_t sym_buflen; \
\
    sym_lookup_name((unsigned long)func, &sym_buf, &sym_buflen); \
\
    NETKIT_LOG("[*] calling: '%s'\n", sym_buf); \
    retv = func( __VA_ARGS__ ); \
    NETKIT_LOG("[*] returned: '%s', retv: %d\n", sym_buf, retv); \
\
    kzfree(sym_buf, sym_buflen); \
\
    retv; \
})

#define NETKIT_PIPELINE_CALL(func, req_buf, req_buflen, res_buf, res_buflen) ({ \
    int retv; \
    char *sym_buf; \
    size_t sym_buflen; \
\
    sym_lookup_name((unsigned long)func, &sym_buf, &sym_buflen); \
\
    NETKIT_LOG("[*] calling: '%s', req_buflen: %lu\n", sym_buf, req_buflen); \
    retv = func(req_buf, req_buflen, res_buf, res_buflen); \
    NETKIT_LOG("[*] returned: '%s', res_buflen: %lu, retv: %d\n", sym_buf, *res_buflen, retv); \
\
    kzfree(sym_buf, sym_buflen); \
\
    retv; \
})

#define NETKIT_PIPELINE_CALL_ERR(func, retv_, res_buf, res_buflen) ({ \
    int retv; \
    char *sym_buf; \
    size_t sym_buflen; \
\
    sym_lookup_name((unsigned long)func, &sym_buf, &sym_buflen); \
\
    NETKIT_LOG("[*] calling: '%s', retv: %d\n", sym_buf, retv_); \
    retv = func(retv_, res_buf, res_buflen); \
    NETKIT_LOG("[*] returned: '%s', res_buflen: %lu, retv: %d\n", sym_buf, *res_buflen, retv); \
\
    kzfree(sym_buf, sym_buflen); \
\
    retv; \
})

#endif