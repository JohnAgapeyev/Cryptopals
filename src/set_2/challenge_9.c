#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../common.h"

int main(void) {
    const char *mesg = "YELLOW SUBMARINE";
    unsigned char *padded = pkcs7_pad((const unsigned char *) mesg, strlen(mesg), 20);
    printf("Set 2 Challenge 9 Padded Message: ");
    for (size_t i = 0; i < strlen(mesg); ++i) {
        printf("%c", padded[i]);
    }
    for (size_t i = 0; i < padded[19]; ++i) {
        printf("%02x", padded[i + 16]);
    }
    printf("\n");
    return EXIT_SUCCESS;
}
