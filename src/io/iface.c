#include <linux/types.h>
#include <linux/err.h>
#include <linux/module.h>

#include "iface.h"
#include "server/server.h"

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
