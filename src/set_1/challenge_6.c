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
    if (len < 80) {
        fprintf(stderr, "Data must be at least twice as long as largest tried key size\n");
        abort();
    }
    unsigned long min_dist = ULONG_MAX;
    unsigned long key_size = 0;
    for (size_t i = 2; i <= 40; ++i) {
        unsigned long dist_1 = hamming_distance(data, data + i, i);
        unsigned long dist_2 = hamming_distance(data + (i * 2), data + (i * 3), i);
        unsigned long dist = (dist_1 + dist_2) / 2;
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
    unsigned char *raw_file = base_64_decode(input, file_size);
    size_t raw_len = (file_size / 4) * 3;

    unsigned long key_size = get_key_size(raw_file, raw_len);
    printf("%lu\n", key_size);

    unsigned char data_bytes[key_size][raw_len / key_size];
    for (size_t i = 0; i < key_size; ++i) {
        for (size_t j = 0; j < raw_len / key_size; ++j) {
            data_bytes[i][j] = raw_file[(j * key_size) + i];
        }
    }

    unsigned char key[key_size];
    unsigned long max_score = 0;

    unsigned char test_buffer[raw_len / key_size];

    for (size_t h = 0; h < key_size; ++h) {
        max_score = 0;
        for (size_t i = 0; i < 128; ++i) {
            memset(test_buffer, i, raw_len / key_size);
            unsigned char *result = xor_buffer(data_bytes[h], test_buffer, raw_len / key_size);
            unsigned long score = plaintext_frequency(result, raw_len / key_size);
            if (score > max_score) {
                max_score = score;
                key[h] = i;
                printf("%c\n", i);
                if (i >= 'a') {
                    for (size_t j = 0; j < raw_len / key_size; ++j) {
                        printf("%c", result);
                    }
                    printf("\n");
                }
            }
            free(result);
        }
    }

    printf("Key: %02x%02x\n", key[0], key[1]);

    unsigned char key_buffer[raw_len];
    fill_repeating(key_buffer, raw_len,(const char *) key, key_size);

    unsigned char *result = xor_buffer(raw_file, key_buffer, raw_len);

    for (size_t i = 0; i < raw_len; ++i) {
        printf("%c", result);
    }
    printf("\n");

    return EXIT_SUCCESS;
}
