#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "../common.h"

unsigned char *aes_key = NULL;

unsigned char *get_target_ciphertext(FILE *fp, size_t *cipher_len) {
    if (aes_key == NULL) {
        aes_key = generate_random_aes_key();
    }
    char input[1025];
    size_t min = UINT_MAX;
    while (fgets(input, 1024, fp)) {
        unsigned char *decoded_unknown = base_64_decode((const unsigned char *) input, strlen(input) - 1);
        size_t decoded_len = ((strlen(input) - 1) / 4) * 3;

        if (decoded_len < min) {
            min = decoded_len;
        }
        free(decoded_unknown);
    }
    unsigned char *ciphertext = checked_malloc(60 * min);
    rewind(fp);

    size_t index = 0;
    while (fgets(input, 1024, fp)) {
        unsigned char *decoded_unknown = base_64_decode((const unsigned char *) input, strlen(input) - 1);
        size_t decoded_len = ((strlen(input) - 1) / 4) * 3;

        unsigned char *encrypted = aes_128_ctr_encrypt(decoded_unknown, decoded_len, aes_key, 0);

        memcpy(ciphertext + (index * min), encrypted, min);
        ++index;

        free(decoded_unknown);
        free(encrypted);
    }

    *cipher_len = 60 * min;

    return ciphertext;
}

void fill_repeating(unsigned char *buffer, const size_t len, const char *key, const size_t key_len) {
    unsigned long index = 0;
    for (size_t i = 0; i < len; ++i) {
        buffer[i] = key[index++ % key_len];
    }
}

int main(void) {
    FILE *fp = fopen("20.txt", "rb");
    if (fp == NULL) {
        fprintf(stderr, "20.txt could not be located\n");
        return EXIT_FAILURE;
    }

    size_t cipher_len;
    unsigned char *ciphertext = get_target_ciphertext(fp, &cipher_len);

    //Minimum ciphertext segment length
    size_t key_size = cipher_len / 60;

    unsigned char data_bytes[key_size][cipher_len / key_size];
    for (size_t i = 0; i < key_size; ++i) {
        for (size_t j = 0; j < cipher_len / key_size; ++j) {
            data_bytes[i][j] = ciphertext[(j * key_size) + i];
        }
    }

    unsigned char key[key_size];
    unsigned long max_score;

    unsigned char test_buffer[cipher_len / key_size];

    for (size_t h = 0; h < key_size; ++h) {
        max_score = 0;
        for (size_t i = 0; i < 256; ++i) {
            memset(test_buffer, i, cipher_len / key_size);
            unsigned char *result = xor_buffer(data_bytes[h], test_buffer, cipher_len / key_size);
            unsigned long score = plaintext_frequency(result, cipher_len / key_size);
            if (score > max_score) {
                max_score = score;
                key[h] = i;
            }
            free(result);
        }
    }
    unsigned char key_buffer[cipher_len];
    fill_repeating(key_buffer, cipher_len, (const char *) key, key_size);
    unsigned char *result = xor_buffer(ciphertext, key_buffer, cipher_len);

    printf("Set 3 Challenge 20 Truncated decrypted string: ");
    print_n_chars(result, cipher_len);

    free(aes_key);
    free(ciphertext);
    free(result);
    fclose(fp);

    return EXIT_SUCCESS;
}
