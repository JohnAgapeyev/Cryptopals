#include <string.h>
#include <stdio.h>
#include "../common.h"

int main(void) {
    unsigned char best_input[10000];
    memset(best_input, 0, 10000);
    unsigned char key = '\0';
    unsigned long max_score = 0;
    FILE *fp = fopen("4.txt", "rb");
    if (fp == NULL) {
        fprintf(stderr, "4.txt could not be found\n");
        exit(EXIT_FAILURE);
    }
    char *input = NULL;
    size_t input_len;
    size_t line_len;
    while ((line_len = getline(&input, &input_len, fp)) > 0) {
        if (line_len != 61) {
            continue;
        }
        unsigned char *raw_input = hex_decode((const unsigned char *) input, line_len - 1);
        size_t raw_len = (line_len - 1) / 2;
        unsigned char test_buffer[raw_len];

        for (size_t i = 0; i < 128; ++i) {
            memset(test_buffer, i, raw_len);
            unsigned char *result = xor_buffer(raw_input, test_buffer, raw_len);
            unsigned long score = plaintext_frequency(result, raw_len);
            if (score > max_score) {
                max_score = score;
                key = i;
                memcpy(best_input, input, line_len);
                printf("New best string: %s\n", input);
            }
            free(result);
        }
        free(raw_input);
    }

    free(input);

    unsigned char test_buffer[61];

    memset(test_buffer, key, 61);
    unsigned char *result = xor_buffer(best_input, test_buffer, 60);
    printf("Set 1 Challenge 4\tInput string: %s\tBest match: %c\tDecoded string: %s\n", input, key, result);

    free(result);
}
