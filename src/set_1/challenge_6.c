#include <string.h>
#include <stdio.h>
#include "../common.h"

int main(void) {
    const char *left = "this is a test";
    const char *right = "wokka wokka!!!";
    unsigned long distance = hamming_distance((const unsigned char *) left, (const unsigned char *) right, strlen(left));
    printf("%lu\n", distance);
    return EXIT_SUCCESS;
}
