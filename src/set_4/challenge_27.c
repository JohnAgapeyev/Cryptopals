#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h>
#include "../common.h"

unsigned char *key = NULL;

unsigned char *encrypt_oracle(const unsigned char *mesg, const size_t len, size_t *out_len) {
    if (key == NULL) {
        key = generate_random_aes_key();
    }
    return aes_128_cbc_encrypt(mesg, len, key, key, out_len);
}

unsigned char *validate_cookie(const unsigned char *mesg, const size_t len) {
    size_t plain_len;
    unsigned char *plaintext = aes_128_cbc_decrypt(mesg, len, key, key, &plain_len);

    for (size_t i = 0; i < plain_len; ++i) {
        if (plaintext[i] < '0') {
            return plaintext;
        }
    }
    free(plaintext);
    return NULL;
}

int main(void) {
    srand(time(NULL));
    unsigned char input[160];
    memset(input, 0, 160);
    size_t cipher_len;
    unsigned char *ciphertext = encrypt_oracle(input, 160, &cipher_len);

    memcpy(ciphertext + 32, ciphertext, 16);
    memset(ciphertext + 16, 0, 16);

    unsigned char *validated = validate_cookie(ciphertext, cipher_len);
    if (validated) {
        unsigned char *recovered_key = xor_buffer(validated, validated + 32, 16);
        printf("Set 4 Challenge 27\nOriginal Key: ");
        for (size_t i = 0; i < 16; ++i) {
            printf("%02x", key[i]);
        }
        printf("\n");
        printf("Recovered key: ");
        for (size_t i = 0; i < 16; ++i) {
            printf("%02x", recovered_key[i]);
        }
        printf("\n");
        free(validated);
        free(recovered_key);
    } else {
        printf("Set 4 Challenge 27 FAILED Unable to generate error plaintext in order to retrieve key\n");
    }

    free(key);
    free(ciphertext);
    return EXIT_SUCCESS;
}
