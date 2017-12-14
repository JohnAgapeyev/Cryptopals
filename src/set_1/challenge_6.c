#include <string.h>
#include <stdio.h>
#include <limits.h>
#include "../common.h"

void fill_repeating(unsigned char *buffer, const size_t len, const char *key, const size_t key_len) {
    unsigned long index = 0;
    for (size_t i = 0; i < len; ++i) {
        buffer[i] = key[index++ % key_len];
    }
}

unsigned long get_key_size(const unsigned char *data, const size_t len) {
    unsigned long min_dist = ULONG_MAX;
    unsigned long key_size = 0;

    for (size_t i = 2; i <= 40; ++i) {
        unsigned long dist = 0;
        for (size_t j = 0; j < len / i; ++j) {
            dist += hamming_distance(data, data + (i * j), i);
        }
        dist /= len / i;
        dist /= i;
        if (dist < min_dist) {
            min_dist = dist;
            key_size = i;
        }
    }
    return key_size;
}

int main(void) {
    FILE *fp = fopen("6.txt", "rb");
    if (fp == NULL) {
        fprintf(stderr, "6.txt could not be found\n");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0, SEEK_END);
    unsigned long long file_size = ftell(fp);
    rewind(fp);

    unsigned char input[file_size];
    size_t index = 0;
    for (size_t i = 0; i < file_size; ++i) {
        int c = fgetc(fp);
        if (c != '\n') {
            input[index++] = c;
        }
    }
    unsigned char *raw_file = base_64_decode(input, index);
    size_t raw_len = ((index / 4) * 3) - 2;

    unsigned long key_size = get_key_size(raw_file, raw_len);

    unsigned char data_bytes[key_size][raw_len / key_size];
    for (size_t i = 0; i < key_size; ++i) {
        for (size_t j = 0; j < raw_len / key_size; ++j) {
            data_bytes[i][j] = raw_file[(j * key_size) + i];
        }
    }

    unsigned char key[key_size];
    unsigned long max_score;

    unsigned char test_buffer[raw_len / key_size];

    for (size_t h = 0; h < key_size; ++h) {
        max_score = 0;
        for (size_t i = 1; i < 128; ++i) {
            memset(test_buffer, i, raw_len / key_size);
            unsigned char *result = xor_buffer(data_bytes[h], test_buffer, raw_len / key_size);
            unsigned long score = plaintext_frequency(result, raw_len / key_size);
            if (score > max_score) {
                max_score = score;
                key[h] = i;
            }
            free(result);
        }
    }
    printf("Set 1 Challenge 6\n");
    printf("Key: ");
    for (size_t j = 0; j < key_size; ++j) {
        printf("%c", key[j]);
    }
    printf("\n\n");

    unsigned char key_buffer[raw_len];
    fill_repeating(key_buffer, raw_len,(const char *) key, key_size);

    unsigned char *result = xor_buffer(raw_file, key_buffer, raw_len);

    printf("Decrypted message: ");
    for (size_t i = 0; i < raw_len; ++i) {
        printf("%c", result[i]);
    }
    printf("\n");

    free(result);
    free(raw_file);

    fclose(fp);

    return EXIT_SUCCESS;
}
