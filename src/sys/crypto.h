#ifndef SYS__CRYPTO_H
#define SYS__CRYPTO_H

#define IS_HEX(val) ((val >= 48 && val <= 57) || (val >= 97 && val <= 102))

void xor_crypt_diff_size(const u8 *req_buf, size_t req_buflen, const u8 *key_buf, size_t key_buflen, u8 *out_buf);
int xor_crypt(size_t req_buflen, const u8 *req_buf_1, const u8 *req_buf_2, u8 **res_buf, size_t *res_buflen);
int aes256cbc_encrypt(const u8 *key, size_t keylen, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen);
int aes256cbc_decrypt(const u8 *key, size_t keylen, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen);
int hex_encode(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);
int hex_decode(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif