#ifndef CORE__AUTH__HANDLERS_H
#define CORE__AUTH__HANDLERS_H

int password_hash_match(const u8* password, size_t password_len);

#endif