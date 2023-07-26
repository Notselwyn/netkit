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
    memset(&(*out_buf)[in_buflen], padding_len, padding_len);

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
 * PKCS#5 or PKCS#7 Padding should be done in advance
 */
static int do_aes_cbc_encrypt(size_t block_size, const u8 *key, size_t keylen, const u8 *iv, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen)
{
	struct crypto_aes_ctx ctx;
    long *intmed_val;
    long pt_val;
    long prev_block_val;
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
        for (size_t j = 0; j < block_size; j += 8) {
            intmed_val = (long*)&((*out_buf)[block_index + j]);
            pt_val = *(long*)&(in_buf[block_index + j]);

            if (block_index > 0)
                prev_block_val = *(long*)&((*out_buf)[block_index + j - block_size]);
            else
                prev_block_val = *(long*)&(iv[j]);

            *intmed_val = pt_val ^ prev_block_val;
        }

        aes_encrypt(&ctx, &(*out_buf)[block_index], &(*out_buf)[block_index]);
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

    NETKIT_LOG("[*] iv: 0x%lx%lx\n", ((long*)iv)[0], ((long*)iv)[1]);

    // ++++ pkcs works
	NETKIT_LOG("[*] applying pkcs#7...\n");
    retv = pkcs_encode(AES_BLOCK_SIZE, in_buf, in_buflen, &buf_padded, &buf_padded_len);
	if (retv < 0)
		goto LAB_OUT_NO_PAD;
    
	NETKIT_LOG("[*] doing cbc encrypt (in_buflen: %lu)...\n", buf_padded_len);
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
