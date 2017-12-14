#include <string.h>
#include <stdio.h>
#include "../common.h"

int main(void) {
    const char *input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    unsigned char *raw_input = hex_decode((const unsigned char *) input, strlen(input));

    unsigned char test_buffer[strlen(input) / 2];

    unsigned char key = '\0';
    unsigned long max_score = 0;

    for (size_t i = 0; i < 128; ++i) {
        memset(test_buffer, i, strlen(input) / 2);
        unsigned char *result = xor_buffer(raw_input, test_buffer, strlen(input) / 2);
        unsigned long score = plaintext_frequency(result, strlen(input) / 2);
        if (score > max_score) {
            max_score = score;
            key = i;
        }
        free(result);
    }

    memset(test_buffer, key, strlen(input) / 2);
    unsigned char *result = xor_buffer(raw_input, test_buffer, strlen(input) / 2);
    printf("Set 1 Challenge 3\tBest match: %c Decoded string: %s\n", key, result);

    free(result);
    free(raw_input);
    return EXIT_SUCCESS;
}
