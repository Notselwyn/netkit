#ifndef CORE__AUTH__AUTH_H
#define CORE__AUTH__AUTH_H

#include <linux/types.h>

int is_password_correct(const u8* password, const size_t password_len);

#endif