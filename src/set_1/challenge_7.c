#include <string.h>
#include <stdio.h>
#include "../common.h"

int main(void) {
    const char *key = "YELLOW SUBMARINE";
    FILE *fp = fopen("7.txt", "rb");
    if (fp == NULL) {
        fprintf(stderr, "7.txt could not be found\n");
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
    unsigned char *plain = aes_128_ecb_decrypt(raw_file, raw_len,(const unsigned char *) key, &plain_len);

    printf("Set 1 Challenge 7\n");
    printf("Decrypted file contents: ");
    for (size_t i = 0; i < plain_len; ++i) {
        printf("%c", plain[i]);
    }
    printf("\n");

    free(plain);
    free(raw_file);
    fclose(fp);
    return EXIT_SUCCESS;
}
