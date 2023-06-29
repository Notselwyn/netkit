#include "packet.h"
#include "auth.h"

static int handle_exec(packet_t* packet)
{
    char* envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
    char* argv[] = {packet->content, NULL};

    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/**
 * Handles the request (based on command id etc)
 */
int process_request(packet_t *packet)
{
    const int (*command_handlers[])(packet_t*) = {
        handle_exec
    };

    is_password_correct(packet->password, sizeof(packet->password));

    // include command >= 0 just in case
    if (packet->command < 0 || packet->command >= sizeof(command_handlers) / 8)
        return -EDOM;

    return command_handlers[packet->command](packet);
}