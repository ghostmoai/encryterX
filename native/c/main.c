/*
 * main.c - CLI en C para EncryptorX
 */

#include "encryptorx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("EncryptorX C CLI v%s\n", ENCRYPTORX_VERSION);
        printf("Uso:\n");
        printf("  %s -e \"mensaje\" [password] [separador: $, %%, &, #]\n", argv[0]);
        printf("  %s -d \"token\" [password]\n", argv[0]);
        printf("  %s --test\n", argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "--test") == 0) {
        const char *msg = "Hola desde C con 64 wrappers NULL y HMAC!";
        printf("[TEST] Cifrando: '%s'\n", msg);
        char *token = encryptorx_encrypt(msg, NULL, '$');
        if (!token) {
            printf("[TEST] ERROR: Fallo al cifrar.\n");
            return 1;
        }
        printf("[TEST] Token generado (longitud %zu):\n%s\n", strlen(token), token);

        char err[256] = {0};
        char *decrypted = encryptorx_decrypt(token, NULL, err, sizeof(err));
        if (!decrypted) {
            printf("[TEST] ERROR al descifrar: %s\n", err);
            free(token);
            return 1;
        }
        printf("[TEST] Descifrado exitoso: '%s'\n", decrypted);
        if (strcmp(msg, decrypted) != 0) {
            printf("[TEST] ERROR: El texto no coincide!\n");
            free(token);
            free(decrypted);
            return 1;
        }
        printf("[TEST] C NATIVE TEST PASSED 100%%!\n");
        free(token);
        free(decrypted);
        return 0;
    }

    if (strcmp(argv[1], "-e") == 0 && argc >= 3) {
        const char *pwd = (argc >= 4 && strlen(argv[3]) > 0) ? argv[3] : NULL;
        char sep = (argc >= 5) ? argv[4][0] : '$';
        char *token = encryptorx_encrypt(argv[2], pwd, sep);
        if (token) {
            printf("%s\n", token);
            free(token);
            return 0;
        } else {
            fprintf(stderr, "Error al cifrar.\n");
            return 1;
        }
    }

    if (strcmp(argv[1], "-d") == 0 && argc >= 3) {
        const char *pwd = (argc >= 4 && strlen(argv[3]) > 0) ? argv[3] : NULL;
        char err[256] = {0};
        char *pt = encryptorx_decrypt(argv[2], pwd, err, sizeof(err));
        if (pt) {
            printf("%s\n", pt);
            free(pt);
            return 0;
        } else {
            fprintf(stderr, "Error: %s\n", err);
            return 1;
        }
    }

    fprintf(stderr, "Comando no reconocido. Ejecute sin argumentos para ver la ayuda.\n");
    return 1;
}
