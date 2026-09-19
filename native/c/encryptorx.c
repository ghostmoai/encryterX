/*
 * encryptorx.c - Implementación nativa en C de EncryptorX v3.0.0
 * Algoritmo Null-Obfuscated Cipher con 64 combinaciones, HMAC-SHA256 y Stream Cipher.
 */

#include "encryptorx.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <wincrypt.h>
#endif

/* -------------------------------------------------------------------------
 * Generador de Bytes Criptográficamente Seguros
 * ------------------------------------------------------------------------- */
static void get_random_bytes(uint8_t *buf, size_t len) {
#if defined(_WIN32) || defined(_WIN64)
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        CryptGenRandom(hProv, (DWORD)len, buf);
        CryptReleaseContext(hProv, 0);
        return;
    }
#endif
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t read_bytes = fread(buf, 1, len, f);
        fclose(f);
        if (read_bytes == len) return;
    }
    /* Fallback pseudoaleatorio */
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)(time(NULL) ^ (uintptr_t)buf));
        seeded = 1;
    }
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(rand() & 0xff);
    }
}

/* -------------------------------------------------------------------------
 * Catálogo de 64 Combinaciones de Envoltorios "NULL"
 * ------------------------------------------------------------------------- */
typedef struct {
    const char *pre;
    const char *post;
} WrapperPair;

static const WrapperPair NULL_WRAPPERS[64] = {
    {"NU", "LL"}, {"nu", "ll"}, {"Nu", "ll"}, {"nU", "ll"},
    {"NU", "ll"}, {"nu", "LL"}, {"Nu", "LL"}, {"nU", "LL"},
    {"NU", "Ll"}, {"nu", "Ll"}, {"Nu", "lL"}, {"NU", "lL"},
    {"LL", "LL"}, {"ll", "ll"}, {"Ll", "ll"}, {"lL", "ll"},
    {"LL", "ll"}, {"ll", "LL"}, {"Ll", "LL"}, {"lL", "LL"},
    {"n", "ull"}, {"N", "ull"}, {"n", "ULL"}, {"N", "ULL"},
    {"n", "Ull"}, {"N", "uLl"}, {"n", "ulL"}, {"N", "UlL"},
    {"nu", "l"},   {"NU", "L"},   {"Nu", "L"},   {"nU", "l"},
    {"null", "null"}, {"NULL", "NULL"}, {"Null", "Null"}, {"nULL", "nULL"},
    {"NulL", "NulL"}, {"nuLL", "nuLL"}, {"NUll", "NUll"}, {"nulL", "nulL"},
    {"null", "NULL"}, {"NULL", "null"}, {"Null", "NULL"}, {"NULL", "Null"},
    {"NL", "UL"}, {"nl", "ul"}, {"Nl", "uL"}, {"nL", "Ul"},
    {"NL", "ul"}, {"nl", "UL"}, {"UL", "NL"}, {"ul", "nl"},
    {"Ul", "Nl"}, {"uL", "nL"},
    {"UN", "LL"}, {"un", "ll"}, {"Un", "ll"}, {"uN", "LL"},
    {"LL", "UN"}, {"ll", "un"}, {"Ll", "un"}, {"lL", "UN"},
    {"NUL", "L"}, {"nul", "l"}
};

static const char SAFE_CHARS[] = "qwrtpsdfghjkmzxcv123456789";
static const char CONNECTORS[] = "=_-";

static int is_valid_separator(char c) {
    return (c == '$' || c == '%' || c == '&' || c == '#');
}

/* -------------------------------------------------------------------------
 * Primitivas Criptográficas (Keystream, XOR, PBKDF2)
 * ------------------------------------------------------------------------- */
static void generate_keystream(const uint8_t *key, size_t key_len,
                               const uint8_t *nonce, size_t nonce_len,
                               size_t length, uint8_t *out_keystream) {
    uint32_t counter = 0;
    size_t generated = 0;
    uint8_t buffer[64 + 32];

    while (generated < length) {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_update(&ctx, nonce, nonce_len);
        uint8_t c_bytes[4];
        c_bytes[0] = (uint8_t)((counter >> 24) & 0xff);
        c_bytes[1] = (uint8_t)((counter >> 16) & 0xff);
        c_bytes[2] = (uint8_t)((counter >> 8) & 0xff);
        c_bytes[3] = (uint8_t)(counter & 0xff);
        sha256_update(&ctx, c_bytes, 4);

        uint8_t h[32];
        sha256_final(&ctx, h);

        size_t to_copy = (length - generated < 32) ? (length - generated) : 32;
        memcpy(out_keystream + generated, h, to_copy);
        generated += to_copy;
        counter++;
    }
}

static void pbkdf2_sha256_simple(const char *password, const uint8_t *salt, size_t salt_len,
                                 uint32_t iterations, uint8_t *out_key_32) {
    size_t pass_len = strlen(password);
    uint8_t msg[128];
    memcpy(msg, salt, salt_len);
    msg[salt_len] = 0; msg[salt_len + 1] = 0; msg[salt_len + 2] = 0; msg[salt_len + 3] = 1;

    uint8_t u[32], t[32];
    hmac_sha256((const uint8_t*)password, pass_len, msg, salt_len + 4, u);
    memcpy(t, u, 32);

    for (uint32_t i = 1; i < iterations; ++i) {
        hmac_sha256((const uint8_t*)password, pass_len, u, 32, u);
        for (int j = 0; j < 32; ++j) {
            t[j] ^= u[j];
        }
    }
    memcpy(out_key_32, t, 32);
}

/* -------------------------------------------------------------------------
 * Ofuscación y Desofuscación
 * ------------------------------------------------------------------------- */
static char* obfuscate_bytes(const uint8_t *data, size_t len) {
    size_t est_size = len * 40 + 64;
    char *out = (char*)malloc(est_size);
    if (!out) return NULL;
    out[0] = '\0';
    size_t pos = 0;

    size_t safe_len = strlen(SAFE_CHARS);
    for (size_t i = 0; i < len; ++i) {
        int w_idx = rand() % 64;
        const WrapperPair *w = &NULL_WRAPPERS[w_idx];

        int pre_n_len = 2 + (rand() % 4);
        for (int p = 0; p < pre_n_len; ++p) {
            out[pos++] = SAFE_CHARS[rand() % safe_len];
        }

        if (rand() % 2) {
            out[pos++] = CONNECTORS[rand() % 3];
        }

        /* Wrapper prefix */
        size_t pre_len = strlen(w->pre);
        memcpy(out + pos, w->pre, pre_len);
        pos += pre_len;

        /* Byte in 2 hex chars */
        sprintf(out + pos, "%02x", data[i]);
        pos += 2;

        /* Wrapper suffix */
        size_t post_len = strlen(w->post);
        memcpy(out + pos, w->post, post_len);
        pos += post_len;

        if (rand() % 2) {
            out[pos++] = CONNECTORS[rand() % 3];
        }

        int post_n_len = 2 + (rand() % 4);
        for (int p = 0; p < post_n_len; ++p) {
            out[pos++] = SAFE_CHARS[rand() % safe_len];
        }
    }
    out[pos] = '\0';
    return out;
}

static uint8_t* deobfuscate_to_bytes(const char *str, size_t *out_len) {
    size_t str_len = strlen(str);
    uint8_t *bytes = (uint8_t*)malloc(str_len / 2 + 16);
    if (!bytes) return NULL;
    size_t byte_count = 0;

    for (size_t i = 0; i < str_len; ) {
        int matched = 0;
        for (int w = 0; w < 64; ++w) {
            size_t pre_len = strlen(NULL_WRAPPERS[w].pre);
            size_t post_len = strlen(NULL_WRAPPERS[w].post);

            if (i + pre_len + 2 + post_len <= str_len) {
                if (strncmp(str + i, NULL_WRAPPERS[w].pre, pre_len) == 0) {
                    char h1 = str[i + pre_len];
                    char h2 = str[i + pre_len + 1];
                    if (isxdigit((unsigned char)h1) && isxdigit((unsigned char)h2)) {
                        if (strncmp(str + i + pre_len + 2, NULL_WRAPPERS[w].post, post_len) == 0) {
                            char hex[3] = {h1, h2, '\0'};
                            bytes[byte_count++] = (uint8_t)strtoul(hex, NULL, 16);
                            i += pre_len + 2 + post_len;
                            matched = 1;
                            break;
                        }
                    }
                }
            }
        }
        if (!matched) {
            i++;
        }
    }
    *out_len = byte_count;
    return bytes;
}

/* -------------------------------------------------------------------------
 * API Pública: Cifrar
 * ------------------------------------------------------------------------- */
char* encryptorx_encrypt(const char *plaintext, const char *password, char delimiter) {
    if (!plaintext) return NULL;
    if (!is_valid_separator(delimiter)) delimiter = '$';

    size_t pt_len = strlen(plaintext);
    uint8_t key[ENCRYPTORX_KEY_SIZE];
    uint8_t nonce[ENCRYPTORX_NONCE_SIZE];
    get_random_bytes(key, ENCRYPTORX_KEY_SIZE);
    get_random_bytes(nonce, ENCRYPTORX_NONCE_SIZE);

    /* Preparar raw_key_package */
    uint8_t raw_key_package[1 + 16 + ENCRYPTORX_KEY_SIZE];
    size_t key_pkg_len = 0;

    if (password && strlen(password) > 0) {
        raw_key_package[0] = 0x01; /* Flag con contraseña */
        uint8_t salt[16];
        get_random_bytes(salt, 16);
        memcpy(raw_key_package + 1, salt, 16);

        uint8_t wrapping_key[32];
        pbkdf2_sha256_simple(password, salt, 16, 100000, wrapping_key);

        uint8_t wrap_ks[32];
        generate_keystream(wrapping_key, 32, salt, 16, 32, wrap_ks);
        for (int i = 0; i < 32; ++i) {
            raw_key_package[1 + 16 + i] = key[i] ^ wrap_ks[i];
        }
        key_pkg_len = 1 + 16 + 32;
    } else {
        raw_key_package[0] = 0x00; /* Flag directo */
        memcpy(raw_key_package + 1, key, ENCRYPTORX_KEY_SIZE);
        key_pkg_len = 1 + ENCRYPTORX_KEY_SIZE;
    }

    /* Cifrar texto */
    uint8_t *ciphertext = (uint8_t*)malloc(pt_len);
    uint8_t *keystream = (uint8_t*)malloc(pt_len);
    generate_keystream(key, ENCRYPTORX_KEY_SIZE, nonce, ENCRYPTORX_NONCE_SIZE, pt_len, keystream);
    for (size_t i = 0; i < pt_len; ++i) {
        ciphertext[i] = ((const uint8_t*)plaintext)[i] ^ keystream[i];
    }
    free(keystream);

    /* HMAC-SHA256 Auth Tag */
    uint8_t auth_key[32];
    static const char AUTH_SALT[] = "ENCRYPTORX_AUTH_TAG_SALT:";
    uint8_t auth_input[sizeof(AUTH_SALT) + 32];
    memcpy(auth_input, AUTH_SALT, strlen(AUTH_SALT));
    memcpy(auth_input + strlen(AUTH_SALT), key, 32);
    sha256(auth_input, strlen(AUTH_SALT) + 32, auth_key);

    size_t mac_data_len = key_pkg_len + ENCRYPTORX_NONCE_SIZE + pt_len;
    uint8_t *mac_data = (uint8_t*)malloc(mac_data_len);
    memcpy(mac_data, raw_key_package, key_pkg_len);
    memcpy(mac_data + key_pkg_len, nonce, ENCRYPTORX_NONCE_SIZE);
    memcpy(mac_data + key_pkg_len + ENCRYPTORX_NONCE_SIZE, ciphertext, pt_len);

    uint8_t full_mac[32];
    hmac_sha256(auth_key, 32, mac_data, mac_data_len, full_mac);
    free(mac_data);

    /* Enmascarar key_package con Nonce */
    uint8_t key_mask[64];
    static const char MASK_SALT[] = "ENCRYPTORX_KEY_MASK";
    generate_keystream(nonce, ENCRYPTORX_NONCE_SIZE, (const uint8_t*)MASK_SALT, strlen(MASK_SALT), key_pkg_len, key_mask);

    uint8_t masked_key[64];
    for (size_t i = 0; i < key_pkg_len; ++i) {
        masked_key[i] = raw_key_package[i] ^ key_mask[i];
    }

    /* Payload = Nonce + Tag + Ciphertext */
    size_t payload_len = ENCRYPTORX_NONCE_SIZE + ENCRYPTORX_TAG_SIZE + pt_len;
    uint8_t *payload = (uint8_t*)malloc(payload_len);
    memcpy(payload, nonce, ENCRYPTORX_NONCE_SIZE);
    memcpy(payload + ENCRYPTORX_NONCE_SIZE, full_mac, ENCRYPTORX_TAG_SIZE);
    memcpy(payload + ENCRYPTORX_NONCE_SIZE + ENCRYPTORX_TAG_SIZE, ciphertext, pt_len);
    free(ciphertext);

    /* Ofuscar ambas partes */
    char *obf_key = obfuscate_bytes(masked_key, key_pkg_len);
    char *obf_payload = obfuscate_bytes(payload, payload_len);
    free(payload);

    size_t total_len = strlen(obf_key) + 1 + strlen(obf_payload) + 1;
    char *result = (char*)malloc(total_len);
    sprintf(result, "%s%c%s", obf_key, delimiter, obf_payload);

    free(obf_key);
    free(obf_payload);
    return result;
}

/* -------------------------------------------------------------------------
 * API Pública: Descifrar
 * ------------------------------------------------------------------------- */
char* encryptorx_decrypt(const char *token, const char *password, char *error_buf, size_t error_buf_len) {
    if (!token) {
        if (error_buf) snprintf(error_buf, error_buf_len, "Token nulo.");
        return NULL;
    }

    char sep_char = '\0';
    const char *sep_pos = NULL;
    for (const char *p = token; *p; ++p) {
        if (is_valid_separator(*p)) {
            sep_char = *p;
            sep_pos = p;
            break;
        }
    }

    if (!sep_pos) {
        if (error_buf) snprintf(error_buf, error_buf_len, "No se encontró ningún separador válido ($%%&#).");
        return NULL;
    }

    size_t key_part_len = sep_pos - token;
    char *obf_key = (char*)malloc(key_part_len + 1);
    memcpy(obf_key, token, key_part_len);
    obf_key[key_part_len] = '\0';

    const char *obf_payload = sep_pos + 1;

    size_t payload_len = 0;
    uint8_t *payload = deobfuscate_to_bytes(obf_payload, &payload_len);
    if (!payload || payload_len < ENCRYPTORX_NONCE_SIZE + ENCRYPTORX_TAG_SIZE) {
        free(obf_key);
        if (payload) free(payload);
        if (error_buf) snprintf(error_buf, error_buf_len, "Payload cifrado corrupto o demasiado corto.");
        return NULL;
    }

    uint8_t nonce[ENCRYPTORX_NONCE_SIZE];
    uint8_t auth_tag[ENCRYPTORX_TAG_SIZE];
    memcpy(nonce, payload, ENCRYPTORX_NONCE_SIZE);
    memcpy(auth_tag, payload + ENCRYPTORX_NONCE_SIZE, ENCRYPTORX_TAG_SIZE);
    size_t ct_len = payload_len - (ENCRYPTORX_NONCE_SIZE + ENCRYPTORX_TAG_SIZE);
    uint8_t *ciphertext = payload + ENCRYPTORX_NONCE_SIZE + ENCRYPTORX_TAG_SIZE;

    size_t masked_key_len = 0;
    uint8_t *masked_key = deobfuscate_to_bytes(obf_key, &masked_key_len);
    free(obf_key);
    if (!masked_key || masked_key_len < 1 + ENCRYPTORX_KEY_SIZE) {
        free(payload);
        if (masked_key) free(masked_key);
        if (error_buf) snprintf(error_buf, error_buf_len, "Clave corrupta o no encontrada.");
        return NULL;
    }

    /* Desenmascarar clave */
    uint8_t key_mask[64];
    static const char MASK_SALT[] = "ENCRYPTORX_KEY_MASK";
    generate_keystream(nonce, ENCRYPTORX_NONCE_SIZE, (const uint8_t*)MASK_SALT, strlen(MASK_SALT), masked_key_len, key_mask);

    uint8_t *raw_key_pkg = (uint8_t*)malloc(masked_key_len);
    for (size_t i = 0; i < masked_key_len; ++i) {
        raw_key_pkg[i] = masked_key[i] ^ key_mask[i];
    }
    free(masked_key);

    uint8_t flag = raw_key_pkg[0];
    uint8_t key[ENCRYPTORX_KEY_SIZE];

    if (flag == 0x01) {
        if (!password || strlen(password) == 0) {
            free(raw_key_pkg);
            free(payload);
            if (error_buf) snprintf(error_buf, error_buf_len, "Este mensaje requiere contraseña.");
            return NULL;
        }
        uint8_t salt[16];
        memcpy(salt, raw_key_pkg + 1, 16);
        uint8_t wrapping_key[32];
        pbkdf2_sha256_simple(password, salt, 16, 100000, wrapping_key);

        uint8_t wrap_ks[32];
        generate_keystream(wrapping_key, 32, salt, 16, 32, wrap_ks);
        for (int i = 0; i < 32; ++i) {
            key[i] = raw_key_pkg[1 + 16 + i] ^ wrap_ks[i];
        }
    } else {
        memcpy(key, raw_key_pkg + 1, ENCRYPTORX_KEY_SIZE);
    }

    /* Verificar HMAC */
    uint8_t auth_key[32];
    static const char AUTH_SALT[] = "ENCRYPTORX_AUTH_TAG_SALT:";
    uint8_t auth_input[sizeof(AUTH_SALT) + 32];
    memcpy(auth_input, AUTH_SALT, strlen(AUTH_SALT));
    memcpy(auth_input + strlen(AUTH_SALT), key, 32);
    sha256(auth_input, strlen(AUTH_SALT) + 32, auth_key);

    size_t mac_data_len = masked_key_len + ENCRYPTORX_NONCE_SIZE + ct_len;
    uint8_t *mac_data = (uint8_t*)malloc(mac_data_len);
    memcpy(mac_data, raw_key_pkg, masked_key_len);
    memcpy(mac_data + masked_key_len, nonce, ENCRYPTORX_NONCE_SIZE);
    memcpy(mac_data + masked_key_len + ENCRYPTORX_NONCE_SIZE, ciphertext, ct_len);
    free(raw_key_pkg);

    uint8_t expected_mac[32];
    hmac_sha256(auth_key, 32, mac_data, mac_data_len, expected_mac);
    free(mac_data);

    /* Comparación en tiempo constante */
    int diff = 0;
    for (int i = 0; i < ENCRYPTORX_TAG_SIZE; ++i) {
        diff |= (auth_tag[i] ^ expected_mac[i]);
    }

    if (diff != 0) {
        free(payload);
        if (error_buf) snprintf(error_buf, error_buf_len, "Fallo de integridad HMAC o contraseña incorrecta.");
        return NULL;
    }

    /* Descifrar texto */
    char *plaintext = (char*)malloc(ct_len + 1);
    uint8_t *keystream = (uint8_t*)malloc(ct_len);
    generate_keystream(key, ENCRYPTORX_KEY_SIZE, nonce, ENCRYPTORX_NONCE_SIZE, ct_len, keystream);

    for (size_t i = 0; i < ct_len; ++i) {
        plaintext[i] = (char)(ciphertext[i] ^ keystream[i]);
    }
    plaintext[ct_len] = '\0';

    free(keystream);
    free(payload);
    return plaintext;
}
