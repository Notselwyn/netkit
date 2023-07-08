#include <linux/types.h>
#include <linux/err.h>
#include <linux/module.h>

#include "iface.h"
#include "server/server.h"

#include "../encoding/iface.h"


/*static dynarr_t *io_module_ops;

int io_register_ops(const struct io_ops *ops)
{
    dynarr_t *dynarr_retv = NULL;

    if (!io_module_ops)
    {
        io_module_ops = dynarr_init(sizeof(io_module_ops));
        if (IS_ERR(io_module_ops))
            return PTR_ERR(io_module_ops);
    }

    // int flex_array_put(struct flex_array *array, int element_nr, void *src, gfp_t flags);
    dynarr_retv = dynarr_append(io_module_ops, ops);
    if (IS_ERR(dynarr_retv))
        return PTR_ERR(dynarr_retv);

    return 0;
}*/


//struct io_ops io_child_ops[] = { io_server_ops };

int io_init(void)
{
    int retv = 0;

    /*for (int i=0; i < sizeof(io_child_ops) / sizeof(io_child_ops[0]); i++)
    {
        retv = io_child_ops[i].init();
        if (retv < 0)
            return retv;
    }*/

    retv = IO_SERVER_OPS.init();
    if (retv < 0)
        return retv;

    return 0;
}

int io_exit(void)
{
    int retv = 0;

    /*for (int i=0; i < sizeof(io_child_ops) / sizeof(io_child_ops[0]); i++)
    {
        retv = io_child_ops[i].exit();
        if (retv < 0)
            return retv;
    }*/

    retv = IO_SERVER_OPS.exit();
    if (retv < 0)
        return retv;

    return 0;
}

/**
 * initial function after receiving data
 * prevents IO children (i.e. server/device) from calling enc_process_start() out of nowhere for clarity
 */ 
int io_process(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    pr_err("[*] calling enc_process()...\n");
    return enc_process(req_buf, req_buflen, res_buf, res_buflen);
}
