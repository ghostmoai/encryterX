/*
 * sha256.h - Implementación pura y portable de SHA-256 y HMAC-SHA-256 en C.
 * Sin dependencias externas (C99 / C11).
 */

#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]);
void sha256(const uint8_t *data, size_t len, uint8_t hash[32]);

/* HMAC-SHA256 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t mac[32]);

#ifdef __cplusplus
}
#endif

#endif /* SHA256_H */
