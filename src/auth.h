#ifndef AUTH_H
#define AUTH_H

#include <linux/types.h>

int is_password_correct(u8* password, size_t password_len);

#endif