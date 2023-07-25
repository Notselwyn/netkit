#include <linux/module.h>
#include <linux/kernel.h>
#include <crypto/aes.h>

#include "crypto.h"

#include "mem.h"
#include "debug.h"

int xor_crypt(u8 key, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen)
{
    *res_buflen = req_buflen;
    *res_buf = kzmalloc(*res_buflen, GFP_KERNEL);

    if (IS_ERR(*res_buf))
    {
        *res_buf = NULL;
        *res_buflen = 0;

        return PTR_ERR(*res_buf);
    }

    // Handle the remaining bytes (if any) using scalar XOR
    for (size_t i = 0; i < req_buflen; i++)
        (*res_buf)[i] = req_buf[i] ^ key;

    return 0;
}

static int pkcs_encode(size_t blocksize, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen)
{
    const size_t padding_len = blocksize - (in_buflen % blocksize);

    *out_buflen = in_buflen + padding_len;
    *out_buf = kzmalloc(*out_buflen, GFP_KERNEL);
    if (IS_ERR(*out_buf)) {
        *out_buf = NULL;
        *out_buflen = 0;
        return PTR_ERR(*out_buf);
    }

    memcpy(*out_buf, in_buf, in_buflen);

    for (size_t i = in_buflen; i < in_buflen + padding_len; i++) {
        (*out_buf)[i] = padding_len;
    }

    return 0;
}

static int get_random_bytes_safe(u8 *bytes, size_t size)
{
	if (wait_for_random_bytes() != 0)
		return -EIO;
    
	get_random_bytes(bytes, size);

	return 0;
}

/**
 * Applies AES-blocklen-CBC
 * 
 * Does not apply padding or validation 
 */
static int do_aes_cbc_encrypt(size_t blocksize, const u8 *key, size_t keylen, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen)
{
	struct crypto_aes_ctx ctx;
    int retv;

    // require multiple of 8 for optimization (this function assumes sizeof(long) == 8)
    if (blocksize % 8 != 0)
		return -EINVAL; 

	retv = aes_expandkey(&ctx, key, keylen);
	if (retv < 0)
		return retv;

    *out_buflen = in_buflen + blocksize - (in_buflen % blocksize);
    *out_buf = kzmalloc(*out_buflen, GFP_KERNEL);
    if (IS_ERR(*out_buf))
    {
        *out_buf = NULL;
        *out_buflen = 0;
        return PTR_ERR(*out_buf);
    }

    // skip IV
    for (int buf_index = 1; buf_index < in_buflen; buf_index += blocksize) {
        // xor with previous block (CBC)
        for (int j = 0; j < blocksize; j += 8)
            *(long*)out_buf[buf_index + j] ^= *(long*)out_buf[buf_index + j - blocksize];

        aes_encrypt(&ctx, *out_buf + buf_index, in_buf + buf_index);
    }

    return 0;
}

int aes256cbc_encrypt(const u8 *key, size_t keylen, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen)
{
    u8 *in_buf_padded;
    size_t in_buf_padded_len;
    u8 *iv;
    int retv;

    // add len parameters for security, since a developer may not know the proper size and cause memory bugs
    if (keylen != AES_KEYSIZE_256)
    {
        retv = -EINVAL;
        goto LAB_OUT_NO_IV;
    }

	NETKIT_LOG("[*] setting iv...\n");
    iv = kzmalloc(in_buflen + AES_BLOCK_SIZE, GFP_KERNEL);
    if (IS_ERR(iv))
    {
        retv = PTR_ERR(iv);
        goto LAB_OUT_NO_IV;
    }

    retv = get_random_bytes_safe(iv, AES_BLOCK_SIZE);
    if (retv < 0)
        goto LAB_OUT_NO_PAD;

    memcpy(iv + AES_BLOCK_SIZE, in_buf, in_buflen);

	NETKIT_LOG("[*] applying pkcs#7...\n");
    retv = pkcs_encode(AES_BLOCK_SIZE, in_buf, in_buflen, &in_buf_padded, &in_buf_padded_len);
	if (retv < 0)
		goto LAB_OUT_NO_PAD;
    
	NETKIT_LOG("[*] doing cbc encrypt...\n");
    retv = do_aes_cbc_encrypt(AES_BLOCK_SIZE, key, AES_KEYSIZE_256, in_buf_padded, in_buf_padded_len, out_buf, out_buflen);

    kzfree(in_buf_padded, in_buf_padded_len);
LAB_OUT_NO_PAD:
    kzfree(iv, in_buflen + AES_BLOCK_SIZE);
LAB_OUT_NO_IV:
    return retv;
}
