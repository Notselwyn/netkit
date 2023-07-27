#include <linux/types.h>
#include <crypto/sha2.h>
#include <linux/string.h>

#include "handlers.h"

#include "../../sys/debug.h"

#define CORRECT_HASH "\x5e\x88\x48\x98\xda\x28\x04\x71\x51\xd0\xe5\x6f\x8d\xc6\x29\x27\x73\x60\x3d\x0d\x6a\xab\xbd\xd6\x2a\x11\xef\x72\x1d\x15\x42\xd8"

int password_hash_match(const u8* password, size_t password_len)
{
	uint8_t hash[SHA256_DIGEST_SIZE];

    sha256(password, password_len, hash);
    if (memcmp(CORRECT_HASH, hash, SHA256_DIGEST_SIZE) != 0)
        return -EKEYREJECTED;

    return 0;
}
