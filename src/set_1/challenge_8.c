#include <string.h>
#include <stdio.h>
#include "../common.h"

int main(void) {
    unsigned char best_input[1024];
    memset(best_input, 0, 1024);

    FILE *fp = fopen("8.txt", "rb");
    if (fp == NULL) {
        fprintf(stderr, "8.txt could not be found\n");
        exit(EXIT_FAILURE);
    }
    char input[1024];
    while (fgets(input, 1024, fp)) {
        unsigned char *raw_input = hex_decode((const unsigned char *) input, strlen(input) - 1);
        size_t raw_len = (strlen(input) - 1) / 2;
        if (detect_ecb(raw_input, raw_len)) {
            memcpy(best_input, input, strlen(input) - 1);
            break;
        }
        free(raw_input);
    }
    printf("Set 1 Challenge 8 ECB string: %s\n", best_input);

    fclose(fp);

    return EXIT_SUCCESS;
}
