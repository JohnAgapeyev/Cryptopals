#include <string.h>
#include <stdio.h>
#include <limits.h>
#include "../common.h"

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

    return EXIT_SUCCESS;
}
