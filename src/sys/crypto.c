#include <linux/module.h>
#include <linux/kernel.h>
#include <crypto/aes.h>

#include "crypto.h"

#include "mem.h"
#include "debug.h"

static void do_xor_inplace(size_t len, const u8 *in_buf_1, const u8 *in_buf_2, u8 *out_buf)
{
    size_t extra_len = len % 8;
    
    for (size_t i = 0; likely(i < len - extra_len); i += 8)
        *(long*)&(out_buf[i]) = *(long*)&(in_buf_1[i]) ^ *(long*)&(in_buf_2[i]);

    for (size_t i = len - extra_len; likely(i < len); i++)
        out_buf[i] = in_buf_1[i] ^ in_buf_2[i];
}

int xor_crypt(size_t req_buflen, const u8 *req_buf_1, const u8 *req_buf_2, u8 **res_buf, size_t *res_buflen)
{
    *res_buflen = req_buflen;
    *res_buf = kzmalloc(*res_buflen, GFP_KERNEL);

    if (IS_ERR(*res_buf))
    {
        *res_buf = NULL;
        *res_buflen = 0;

        return PTR_ERR(*res_buf);
    }

    do_xor_inplace(req_buflen, req_buf_1, req_buf_2, *res_buf);

    return 0;
}

static int pkcs_encode(size_t block_size, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen)
{
    size_t padding_len = block_size - (in_buflen % block_size);
    if (padding_len == block_size)
        padding_len = 0;

    *out_buflen = in_buflen + padding_len;
    *out_buf = kzmalloc(*out_buflen, GFP_KERNEL);
    if (IS_ERR(*out_buf)) {
        *out_buf = NULL;
        *out_buflen = 0;
        return PTR_ERR(*out_buf);
    }

    memcpy(*out_buf, in_buf, in_buflen);
    memset(&(*out_buf)[in_buflen], padding_len, padding_len);

    return 0;
}


static int pkcs_decode(size_t block_size, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen)
{
    size_t padding_len;
    
    padding_len = in_buf[(ssize_t)in_buflen - 1];
    if (padding_len >= block_size || padding_len == 0)
    {
        // padding is not valid, so there is no padding
        padding_len = 0;
        goto LAB_DECODE;
    }

    // check for 0x01, 0x0202, 0x030303, etc.
    for (size_t i=0; i < padding_len; i++)
    {
        if (in_buf[in_buflen - i - 1] != padding_len)
        {
            // padding is not valid, so there is no padding
            padding_len = 0;
            goto LAB_DECODE;
        }
    }

LAB_DECODE:
    *out_buflen = in_buflen - padding_len;
    *out_buf = kzmalloc(*out_buflen, GFP_KERNEL);
    if (IS_ERR(*out_buf)) {
        *out_buf = NULL;
        *out_buflen = 0;
        return PTR_ERR(*out_buf);
    }

    memcpy(*out_buf, in_buf, *out_buflen);

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
 * Encrypts AES-blocklen-CBC
 * 
 * PKCS#5 or PKCS#7 Padding should be done in advance
 */
static int do_aes_cbc_encrypt(size_t block_size, const u8 *key, size_t keylen, const u8 *iv, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen)
{
	struct crypto_aes_ctx ctx;
    int retv;

    // require multiple of 8 for optimization (this function assumes sizeof(long) == 8)
    if (block_size % 8 != 0)
		return -EINVAL; 

	retv = aes_expandkey(&ctx, key, keylen);
	if (retv < 0)
		return retv;

    *out_buflen = in_buflen;
    *out_buf = kzmalloc(*out_buflen, GFP_KERNEL);
    if (IS_ERR(*out_buf))
    {
        *out_buf = NULL;
        *out_buflen = 0;
        return PTR_ERR(*out_buf);
    }

    // skip IV
    for (size_t block_index = 0; block_index < in_buflen; block_index += block_size) {
        // xor prev ct block (or IV) with pt block to get intermediate value to encrypt
        if (block_index > 0)
            do_xor_inplace(block_size, &(*out_buf)[block_index - block_size], &in_buf[block_index], &(*out_buf)[block_index]);
        else
            do_xor_inplace(block_size, iv, &in_buf[block_index], &(*out_buf)[block_index]);

        aes_encrypt(&ctx, &(*out_buf)[block_index], &(*out_buf)[block_index]);
    }

    return 0;
}

/**
 * Decrypts AES-blocklen-CBC
 * 
 * PKCS#5 or PKCS#7 Padding should be done in advance
 */
static int do_aes_cbc_decrypt(size_t block_size, const u8 *key, size_t keylen, const u8 *iv, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen)
{
	struct crypto_aes_ctx ctx;
    int retv;

    // require multiple of 8 for optimization (this function assumes sizeof(long) == 8)
    if (block_size % 8 != 0 || in_buflen % block_size != 0)
		return -EINVAL; 

	retv = aes_expandkey(&ctx, key, keylen);
	if (retv < 0)
		return retv;

    *out_buflen = in_buflen;
    *out_buf = kzmalloc(*out_buflen, GFP_KERNEL);
    if (IS_ERR(*out_buf))
    {
        *out_buf = NULL;
        *out_buflen = 0;
        return PTR_ERR(*out_buf);
    }

    // skip IV
    for (size_t block_index = 0; block_index < in_buflen; block_index += block_size) {
        // decrypt ct (in) -> pt (out)
        aes_decrypt(&ctx, &(*out_buf)[block_index], &in_buf[block_index]);

        // xor prev ct block (or IV) with intermediate to get pt block
        if (block_index > 0)
            do_xor_inplace(block_size, &in_buf[block_index - block_size], &(*out_buf)[block_index], &(*out_buf)[block_index]);
        else
            do_xor_inplace(block_size, iv, &(*out_buf)[block_index], &(*out_buf)[block_index]);
    }

    return 0;
}

int aes256cbc_encrypt(const u8 *key, size_t keylen, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen)
{
    u8 *buf_padded;
    size_t buf_padded_len;
    u8 *buf_encrypted;
    size_t buf_encrypted_len;
    u8 iv[AES_BLOCK_SIZE];
    int retv;

    // add len parameters for security, since a developer may not know the proper size and cause memory bugs
    if (keylen != AES_KEYSIZE_256)
    {
        retv = -EINVAL;
        goto LAB_OUT_NO_PAD;
    }

    retv = get_random_bytes_safe(iv, AES_BLOCK_SIZE);
    if (retv < 0)
        goto LAB_OUT_NO_PAD;

    retv = pkcs_encode(AES_BLOCK_SIZE, in_buf, in_buflen, &buf_padded, &buf_padded_len);
	if (retv < 0)
		goto LAB_OUT_NO_PAD;

    retv = do_aes_cbc_encrypt(AES_BLOCK_SIZE, key, AES_KEYSIZE_256, iv, buf_padded, buf_padded_len, &buf_encrypted, &buf_encrypted_len);
    if (retv < 0)
        goto LAB_OUT_NO_ENCRYPT;

    *out_buflen = AES_BLOCK_SIZE + buf_encrypted_len;
    *out_buf = kzmalloc(*out_buflen, GFP_KERNEL);
    if (IS_ERR(*out_buf))
    {
        retv = PTR_ERR(*out_buf);
        *out_buf = NULL;
        *out_buflen = 0;
        goto LAB_OUT;
    }

    memcpy(*out_buf, iv, AES_BLOCK_SIZE);
    memcpy(*out_buf + AES_BLOCK_SIZE, buf_encrypted, buf_encrypted_len);

LAB_OUT:
    kzfree(buf_encrypted, buf_encrypted_len);
LAB_OUT_NO_ENCRYPT:
    kzfree(buf_padded, buf_padded_len);
LAB_OUT_NO_PAD:
    return retv;
}

int aes256cbc_decrypt(const u8 *key, size_t keylen, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen)
{
    u8 *buf_decrypted;
    size_t buf_decrypted_len;
    u8 iv[AES_BLOCK_SIZE];
    int retv;

    // add len parameters for security, since a developer may not know the proper size and cause memory bugs
    // there need to be atleast 2 blocks: iv + content
    if (keylen != AES_KEYSIZE_256 || in_buflen < AES_BLOCK_SIZE * 2)
    {
        retv = -EINVAL;
        goto LAB_OUT_NO_DECRYPT;
    }

    memcpy(iv, in_buf, AES_BLOCK_SIZE);

    retv = do_aes_cbc_decrypt(AES_BLOCK_SIZE, key, AES_KEYSIZE_256, iv, &in_buf[AES_BLOCK_SIZE], in_buflen - AES_BLOCK_SIZE, &buf_decrypted, &buf_decrypted_len);
    if (retv < 0)
        goto LAB_OUT_NO_DECRYPT;

    retv = pkcs_decode(AES_BLOCK_SIZE, buf_decrypted, buf_decrypted_len, out_buf, out_buflen);
	if (retv < 0)
		goto LAB_OUT;
LAB_OUT:
    kzfree(buf_decrypted, buf_decrypted_len);
LAB_OUT_NO_DECRYPT:
    return retv;
}
