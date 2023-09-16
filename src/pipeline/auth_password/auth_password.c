#include <linux/types.h>
#include <linux/string.h>

#include "auth_password.h"

#include "../../sys/debug.h"

int layer_auth_password_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen, size_t index)
{
	uint8_t hash[SHA256_DIGEST_SIZE];
    size_t password_buflen;

    // require null-byte at end of password
    password_buflen = strnlen(req_buf, req_buflen);
    if (password_buflen == req_buflen)
        return -EINVAL;

    // does not include nullbyte
    NETKIT_LOG("[*] password: '%s'\n", req_buf);
    sha256(req_buf, password_buflen, hash);

    if (memcmp(CORRECT_HASH, hash, SHA256_DIGEST_SIZE) != 0)
        return -EKEYREJECTED;

    // allow OOB ptr with size 0
    return call_next_layer(req_buf + password_buflen + 1, req_buflen - password_buflen - 1, res_buf, res_buflen, index+1);
}