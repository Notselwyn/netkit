#ifndef NETKIT_H
#define NETKIT_H

#define CONFIG_NETKIT_DEBUG 1
#define CONFIG_NETKIT_STEALTH_FORCE 1

// used for the self destruct cmd
extern struct module *netkit_module;

#define CONFIG_NETKIT_STEALTH ((!CONFIG_NETKIT_DEBUG) || CONFIG_NETKIT_STEALTH_FORCE)

#endif