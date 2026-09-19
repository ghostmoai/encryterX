#ifndef ENCRYPTORX_H
#define ENCRYPTORX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ENCRYPTORX_VERSION "3.0.0"
#define ENCRYPTORX_KEY_SIZE 32
#define ENCRYPTORX_NONCE_SIZE 16
#define ENCRYPTORX_TAG_SIZE 16

/*
 * Cifra un texto en claro usando el algoritmo Null-Obfuscated Cipher.
 * delimiter: '$', '%', '&', '#' (por defecto '$')
 * password: clave opcional (NULL si es auto-descifrable)
 * Retorna una cadena asignada con malloc (liberar con free()).
 */
char* encryptorx_encrypt(const char *plaintext, const char *password, char delimiter);

/*
 * Descifra un token cifrado.
 * password: clave opcional (NULL si es auto-descifrable)
 * Retorna una cadena asignada con malloc (liberar con free()),
 * o NULL si falla (se copia el error en error_buf si no es NULL).
 */
char* encryptorx_decrypt(const char *token, const char *password, char *error_buf, size_t error_buf_len);

#ifdef __cplusplus
}
#endif

#endif /* ENCRYPTORX_H */
