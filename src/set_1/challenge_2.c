#include <string.h>
#include <stdio.h>
#include "../common.h"

int main(void) {
    const char *input = "1c0111001f010100061a024b53535009181c";
    const char *xor = "686974207468652062756c6c277320657965";
    const char *result = "746865206b696420646f6e277420706c6179";

    unsigned char *raw_input = hex_decode((const unsigned char *) input, strlen(input));
    unsigned char *raw_xor = hex_decode((const unsigned char *) xor, strlen(xor));
    unsigned char *buffer = xor_buffer(raw_input, raw_xor, strlen(input) / 2);
    unsigned char *hex_result = hex_encode(buffer, strlen(input) / 2);

    if (strcmp((const char *) hex_result, result) == 0) {
        printf("Set 1 Challenge 2 Successful.\nDesired output: %s\nResulting output: %s\n", result, hex_result);
    } else {
        printf("Set 1 Challenge 2 FAILED.\nDesired output: %s\nResulting output: %s\n", result, hex_result);
    }

    free(raw_input);
    free(raw_xor);
    free(hex_result);
    free(buffer);
}
