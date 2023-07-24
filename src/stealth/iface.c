#include "iface.h"

#include "module/module.h"

int stealth_init(void)
{
    return module_init_();
}

/**
 * do the bare minimum to get a successfull silent and clean exit
 */
int stealth_exit(void)
{
    return module_exit_();
}