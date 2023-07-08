#ifndef AUTH_H
#define AUTH_H

#include <linux/types.h>

int is_password_correct(const u8* password, const size_t password_len);

#endif