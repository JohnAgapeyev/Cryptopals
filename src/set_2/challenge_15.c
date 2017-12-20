#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../common.h"

int main(void) {
    const char *good = "ICE ICE BABY\x04\x04\x04\x04";
    const char *bad_1 = "ICE ICE BABY\x05\x05\x05\x05";
    const char *bad_2 = "ICE ICE BABY\x01\x02\x03\x04";

    if (!validate_pkcs7_padding((const unsigned char *) good, strlen(good))) {
        fprintf(stderr, "Padding validation produced wrong result\n");
        abort();
    }
    if (validate_pkcs7_padding((const unsigned char *) bad_1, strlen(bad_1))) {
        fprintf(stderr, "Padding validation produced wrong result\n");
        abort();
    }
    if (validate_pkcs7_padding((const unsigned char *) bad_2, strlen(bad_2))) {
        fprintf(stderr, "Padding validation produced wrong result\n");
        abort();
    }
    printf("Set 2 Challenge 15 All padding examples validated as expected\n");

    return EXIT_SUCCESS;
}
