int xor_crypt(u8 key, const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);
int aes256cbc_encrypt(const u8 *key, size_t keylen, const u8 *in_buf, size_t in_buflen, u8 **out_buf, size_t *out_buflen);