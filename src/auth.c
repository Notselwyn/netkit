#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/device.h>
#include <crypto/sha2.h>

#include "auth.h"
#include "packet.h"

#define CORRECT_HASH "\x5e\x88\x48\x98\xda\x28\x04\x71\x51\xd0\xe5\x6f\x8d\xc6\x29\x27\x73\x60\x3d\x0d\x6a\xab\xbd\xd6\x2a\x11\xef\x72\x1d\x15\x42\xd8"

int is_password_correct(u8* password, size_t password_len)
{
	uint8_t hash[SHA256_DIGEST_SIZE];

    sha256(password, password_len, hash);

    for (int i=0; i < SHA256_DIGEST_SIZE; i++)
        if (CORRECT_HASH[i] != hash[i])
            return -1;

    return 0;
}