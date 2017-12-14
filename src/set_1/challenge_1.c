#include <string.h>
#include <stdio.h>
#include "../common.h"

int main(void) {
    const char *testString = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const char *resultString = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    unsigned char *decoded = hex_decode((const unsigned char *) testString, strlen(testString));
    unsigned char *buffer = base_64_encode((const unsigned char *) decoded, strlen(testString) / 2);

    if (strcmp((const char *) buffer, resultString) == 0) {
        printf("Set 1 Challenge 1 Successful.\nDesired output: %s\nResulting output: %s\n", resultString, buffer);
    } else {
        printf("Set 1 Challenge 1 FAILED.\nDesired output: %s\nResulting output: %s\n", resultString, buffer);
    }

    free(decoded);
    free(buffer);
    return EXIT_SUCCESS;
}
