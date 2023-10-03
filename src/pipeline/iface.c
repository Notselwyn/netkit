#include "iface.h"

#include "../sys/debug.h"
#include "../cmd/iface.h"


// performs all ->encodes in pipeline array, then cmd, then ->decodes; if error happens then it calls every ->handle_err func in stack pop order
int pipeline_process(const struct pipeline_ops **pl_ops_arr, u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    int index;
    pipeline_func_t *func;
    pipeline_func_handle_err_t *func_err;
    u8 *middle_buf;
    size_t middle_buflen;
    int retv;

    // decode each layer
    for (index = 0; pl_ops_arr[index] != NULL; index++)
    {
        func = pl_ops_arr[index]->decode;
        if (func == NULL)
            continue;

        retv = NETKIT_PIPELINE_CALL(func, req_buf, req_buflen, &middle_buf, &middle_buflen);
        if (retv < 0)
            goto LAB_HANDLE_ERR;

        req_buf = middle_buf;
        req_buflen = middle_buflen;
    }

    // execute commands
    retv = NETKIT_PIPELINE_CALL(cmd_process, req_buf, req_buflen, &middle_buf, &middle_buflen);
    index--;
    if (retv < 0)
        goto LAB_HANDLE_ERR;

    req_buf = middle_buf;
    req_buflen = middle_buflen;

LAB_ENCODE:
    // encode. start with the previous level
    for (; index >= 0; index--)
    {
        func = pl_ops_arr[index]->encode;
        if (func == NULL)
            continue;

        retv = NETKIT_PIPELINE_CALL(func, req_buf, req_buflen, &middle_buf, &middle_buflen);
        if (retv < 0)
            goto LAB_HANDLE_ERR;

        req_buf = middle_buf;
        req_buflen = middle_buflen;
    }

    *res_buf = req_buf;
    *res_buflen = req_buflen;

    return 0;

LAB_HANDLE_ERR:
    // handle errors. start with the current level, so http can catch http errors
    for (; index >= 0; index--)
    {
        // when error is caught, go to next level
        func_err = pl_ops_arr[index]->handle_err;
        if (func_err == NULL)
            continue;

        retv = NETKIT_PIPELINE_CALL_ERR(func_err, retv, &middle_buf, &middle_buflen);

        req_buf = middle_buf;
        req_buflen = middle_buflen;
        
        // here for index == 0, since index-- == -1, so no LAB_ENCODE
        if (retv >= 0)
        {
            index--;
            goto LAB_ENCODE;
        }
    }
    
    // no need to clean here (res_buf is not set and req_buf is already cleared)

    return retv;
}