#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../common.h"

int main(void) {
    const char *key = "YELLOW SUBMARINE";
    unsigned char iv[16];
    memset(iv, 0, 16);

    FILE *fp = fopen("10.txt", "rb");
    if (fp == NULL) {
        fprintf(stderr, "10.txt could not be found\n");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0, SEEK_END);
    unsigned long long file_size = ftell(fp);
    rewind(fp);

    unsigned char input[file_size];
    size_t index = 0;
    for (size_t i = 0; i < file_size; ++i) {
        int c = fgetc(fp);
        if (c != '\n') {
            input[index++] = c;
        }
    }
    unsigned char *raw_file = base_64_decode(input, index);
    size_t raw_len = ((index / 4) * 3);

    size_t plain_len;
    unsigned char *plaintext = aes_128_cbc_decrypt(raw_file, raw_len, (const unsigned char *) key, iv, &plain_len);

    printf("Set 2 Challenge 10 Decrypted File contents: ");
    print_n_chars(plaintext, plain_len);

    return EXIT_SUCCESS;
}
