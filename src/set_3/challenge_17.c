#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include "../common.h"

unsigned char *key = NULL;
unsigned char *iv = NULL;
unsigned char *unknown_strings[10];

const char *unknown_source[10] = {
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
};

void fill_unknown(void) {
    for (int i = 0; i < 10; ++i) {
        unsigned char *decoded_unknown = base_64_decode((const unsigned char *) unknown_source[i], strlen(unknown_source[i]));
        size_t decoded_len = ((strlen(unknown_source[i]) / 4) * 3);

        unsigned char null_terminated[decoded_len + 1];
        memcpy(null_terminated, decoded_unknown, decoded_len);
        null_terminated[decoded_len] = '\0';

        unknown_strings[i] = checked_malloc(decoded_len + 1);

        memcpy(unknown_strings[i], null_terminated, decoded_len + 1);

        free(decoded_unknown);
    }
}

unsigned char *encrypt_oracle(size_t *out_len) {
    if (key == NULL) {
        key = generate_random_aes_key();
    }
    if (iv != NULL) {
        free(iv);
    }
    iv = generate_random_aes_key();

    size_t index = rand() % 10;

    unsigned char *rtn = aes_128_cbc_encrypt(unknown_strings[index], strlen((const char *) unknown_strings[index]), key, iv, out_len);
    return rtn;
}

bool padding_oracle(const unsigned char *mesg, const size_t len) {
    size_t plain_len;
    unsigned char *plaintext = aes_128_cbc_decrypt(mesg, len, key, iv, &plain_len);

    bool rtn = validate_pkcs7_padding(plaintext, plain_len);
    free(plaintext);
    return rtn;
}

unsigned char *decrypt_block(const unsigned char *prev, const unsigned char *target, const size_t len) {
    unsigned char *out = checked_calloc((len / 2) + 1, sizeof(unsigned char));
    unsigned char buffer[len];
    for (int i = len - 1; i >= 16; --i) {
        for (unsigned int j = 0; j < 256; ++j) {
            /*
             * Don't try the number equal to the padding since the later xors
             * would cancel each other out, returning a false positive.
             * One exception is the last byte of the padding, where the guess
             * must be equal to the padding, hence the second predicate.
             */
            if (j == (len - i) && out[i + 1 - 16] != (len - i)) {
                continue;
            }
            memcpy(buffer, prev, len / 2);
            memcpy(buffer + (len / 2), target, len / 2);

            for (int k = len - 1; k > i; --k) {
                buffer[k - 16] ^= out[k - 16] ^ (len - i);
            }

            buffer[i - 16] ^= j ^ (len - i);

            if (padding_oracle(buffer, len)) {
                out[i - 16] = j;
                break;
            }
        }
    }
    return out;
}

unsigned char *decrypt_mesg(const unsigned char *mesg, const size_t len) {
    unsigned char *out = checked_malloc(len);

    unsigned char *initial_block = decrypt_block(iv, mesg, 32);
    memcpy(out, initial_block, 16);
    free(initial_block);

    for (size_t i = 0; i < (len / 16) - 1; ++i) {
        unsigned char *plain_block = decrypt_block(mesg + (i * 16), mesg + ((i + 1) * 16), 32);
        memcpy(out + ((i + 1) * 16), plain_block, 16);
        free(plain_block);
    }
    return out;
}

int main(void) {
    srand(time(NULL));
    fill_unknown();

    size_t len;
    unsigned char *ciphertext = encrypt_oracle(&len);

    unsigned char *plaintext = decrypt_mesg(ciphertext, len);

    //Remove padding from length
    len -= plaintext[len - 1];

    printf("Set 3 Challenge 17 Decrypted string: ");
    print_n_chars(plaintext, len);

    free(plaintext);
    free(ciphertext);
    free(key);
    free(iv);

    for (int i = 0; i < 10; ++i) {
        free(unknown_strings[i]);
    }

    return EXIT_SUCCESS;
}
