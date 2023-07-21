#include <linux/types.h>
#include <linux/err.h>
#include <linux/module.h>

#include "iface.h"
#include "server/server.h"

#include "../encoding/iface.h"

int io_init(void)
{
    int retv = 0;

    retv = server_init();
    if (retv < 0)
        return retv;

    return 0;
}

int io_exit(void)
{
    int retv = 0;

    retv = server_exit();
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
