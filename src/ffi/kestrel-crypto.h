#ifndef KESTREL_CRYPTO_H
#define KESTREL_CRYPTO_H

#include <stddef.h>

void scrypt(
    const unsigned char* password,
    size_t password_len,
    const unsigned char* salt,
    size_t salt_len,
    unsigned int n,
    unsigned int r,
    unsigned int p,
    unsigned char* derived_key,
    size_t dk_len
);

#endif

