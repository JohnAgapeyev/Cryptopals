#include <string.h>
#include <stdio.h>
#include "../common.h"

void fill_repeating(unsigned char *buffer, const size_t len, const char *key, const size_t key_len) {
    unsigned long index = 0;
    for (size_t i = 0; i < len; ++i) {
        buffer[i] = key[index++ % key_len];
    }
}

int main(void) {
    const char *input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const char *result = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    const char *key = "ICE";

    unsigned char key_buffer[strlen(input)];
    fill_repeating(key_buffer, strlen(input), key, strlen(key));

    unsigned char *xor = xor_buffer((const unsigned char *) input, key_buffer, strlen(input));
    unsigned char *hex = hex_encode(xor, strlen(input));

    if (strncmp((const char *) hex, result, strlen(result)) == 0) {
        printf("Set 1 Challenge 5 Successful.\nDesired output: %s\nResulting output: %s\n", result, hex);
    } else {
        printf("Set 1 Challenge 5 FAILED.\nDesired output: %s\nResulting output: %s\n", result, hex);
    }

    free(xor);
    free(hex);
}
