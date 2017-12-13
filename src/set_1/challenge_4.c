#include <string.h>
#include <stdio.h>
#include "../common.h"

int main(void) {
    unsigned char best_input[128];
    memset(best_input, 0, 128);
    unsigned char key = '\0';
    unsigned long max_score = 0;
    FILE *fp = fopen("4.txt", "rb");
    if (fp == NULL) {
        fprintf(stderr, "4.txt could not be found\n");
        exit(EXIT_FAILURE);
    }
    char input[128];
    while (fgets(input, 128, fp)) {
        if (strlen(input) != 61) {
            continue;
        }
        unsigned char *raw_input = hex_decode((const unsigned char *) input, strlen(input) - 1);
        size_t raw_len = (strlen(input) - 1) / 2;
        unsigned char test_buffer[raw_len];

        for (size_t i = 0; i < 128; ++i) {
            memset(test_buffer, i, raw_len);
            unsigned char *result = xor_buffer(raw_input, test_buffer, raw_len);
            unsigned long score = plaintext_frequency(result, raw_len);
            if (score > max_score) {
                max_score = score;
                key = i;
                strcpy((char *)best_input, input);
            }
            free(result);
        }
        free(raw_input);
    }
    best_input[strlen((char *) best_input) - 1] = '\0';
    unsigned char *raw_best_input = hex_decode(best_input, strlen((char *) best_input));
    size_t best_raw_len = strlen((char *) best_input) / 2;

    unsigned char test_buffer[best_raw_len];
    memset(test_buffer, key, best_raw_len);

    unsigned char *result = xor_buffer(raw_best_input, test_buffer, best_raw_len);

    printf("Set 1 Challenge 4 Input string: %s Best match: %c Decoded string: %s\n", best_input, key, result);

    free(raw_best_input);
    free(result);
}
