#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "../common.h"

unsigned char *aes_key = NULL;
unsigned short nonce = 0;

unsigned char *get_ciphertext(size_t *cipher_len) {
    if (aes_key == NULL) {
        aes_key = generate_random_aes_key();
        nonce = rand() % USHRT_MAX;
    }
    const char *key = "YELLOW SUBMARINE";
    FILE *fp = fopen("25.txt", "rb");
    if (fp == NULL) {
        fprintf(stderr, "25.txt could not be found\n");
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

    unsigned char *plaintext = aes_128_ecb_decrypt(raw_file, raw_len, (const unsigned char *) key, NULL);

    unsigned char *ciphertext = aes_128_ctr_encrypt(plaintext, raw_len, aes_key, nonce);

    if (cipher_len) {
        *cipher_len = raw_len;
    }

    fclose(fp);
    free(raw_file);
    free(plaintext);

    return ciphertext;
}

/*
 * I'm aware it'd be better to decrypt and modify only the affected parts of the message.
 * But my functions for encryption/decryption allocate their own buffer for every call,
 * so it's easier/cleaner to simply decrypt the whole thing, modify it, then re-encrypt the entire mesg.
 * The speed penalty for decrypting the whole message isn't an issue anyhow.
 */
unsigned char *edit(const unsigned char *mesg, const size_t len, const size_t offset, const unsigned char *new, const size_t new_len) {
    if (offset >= len || new_len + offset > len) {
        return NULL;
    }

    unsigned char *plaintext = aes_128_ctr_decrypt(mesg, len, aes_key, nonce);

    memcpy(plaintext + offset, new, new_len);

    unsigned char *modified = aes_128_ctr_encrypt(plaintext, len, aes_key, nonce);

    free(plaintext);

    return modified;
}

/**
 * I'm sure I could do this 1 block at a time to match the "spirit" of what an edit function
 * would be used for.
 * But since I have arbitrary modification of the plaintext, I just brute-force every possible
 * character, and check if the bytes match between the modified and original ciphertexts.
 */
int main(void) {
    size_t cipher_len;
    unsigned char *ciphertext = get_ciphertext(&cipher_len);

    unsigned char plaintext[cipher_len];

    unsigned char input[cipher_len];
    for (unsigned char i = 0; i < UCHAR_MAX; ++i) {
        memset(input, i, cipher_len);
        unsigned char *modified = edit(ciphertext, cipher_len, 0, input, cipher_len);

        for (size_t j = 0; j < cipher_len; ++j) {
            if (modified[j] == ciphertext[j]) {
                plaintext[j] = i;
            }
        }
        free(modified);
    }

    printf("Set 4 Challenge 25 Decrypted message: ");
    print_n_chars(plaintext, cipher_len);

    return EXIT_SUCCESS;
}
