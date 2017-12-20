#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../common.h"

unsigned char *random_encryption(const unsigned char *mesg, const size_t len, size_t *out_len) {
    unsigned char *key = generate_random_aes_key();

    //Random 5-10
    unsigned int garbage_count = (rand() % 5) + 5;

    unsigned char garbage_data[garbage_count];
    for (size_t i = 0; i < garbage_count; ++i) {
        garbage_data[i] = rand();
    }

    unsigned char plaintext[len + (garbage_count * 2)];

    memcpy(plaintext, garbage_data, garbage_count);
    memcpy(plaintext + garbage_count, mesg, len);
    memcpy(plaintext + garbage_count + len, garbage_data, garbage_count);

    if (rand() % 2) {
        printf("Rand has chosen to use ECB\n");
        unsigned char *padded = pkcs7_pad(plaintext, len + (garbage_count * 2), 16);
        unsigned long padded_len = get_padded_length(len + (garbage_count * 2), 16);
        unsigned char *rtn = aes_128_ecb_encrypt(padded, padded_len, key, out_len);
        free(key);
        free(padded);
        return rtn;
    }
    printf("Rand has chosen to use CBC\n");

    unsigned char iv[16];
    for (size_t i = 0; i < 16; ++i) {
        iv[i] = rand();
    }

    unsigned char *rtn = aes_128_cbc_encrypt(plaintext, len + (garbage_count * 2), key, iv, out_len);
    free(key);
    return rtn;
}

int main(void) {
    const char *message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    srand(time(NULL));

    printf("Set 2 Challenge 11\n");
    for (int i = 0; i < 10; ++i) {
        size_t cipher_len;
        unsigned char *random_ciphertext = random_encryption((const unsigned char *) message, strlen(message), &cipher_len);

        if (detect_ecb(random_ciphertext, cipher_len)) {
            printf("This is ECB data!\n");
        } else {
            printf("This is CBC data!\n");
        }
        free(random_ciphertext);
    }

    return EXIT_SUCCESS;
}
