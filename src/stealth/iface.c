#include "iface.h"

#include "module/module.h"

int stealth_init(void)
{
    return module_init_();
}

int stealth_exit(void)
{
    return module_exit_();
}