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

    unsigned char *padded = pkcs7_pad(unknown_strings[index], strlen((const char *) unknown_strings[index]), 16);
    unsigned long padded_len = get_padded_length(strlen((const char *) unknown_strings[index]), 16);
    unsigned char *rtn = aes_128_cbc_encrypt(padded, padded_len, key, iv, out_len);
    free(padded);
    return rtn;
}

bool padding_oracle(const unsigned char *mesg, const size_t len) {
    size_t plain_len;
    unsigned char *plaintext = aes_128_cbc_decrypt(mesg, len, key, iv, &plain_len);

    bool rtn = validate_pkcs7_padding(plaintext, plain_len);
    free(plaintext);
    return rtn;
}

int main(void) {
    srand(time(NULL));
    fill_unknown();

    size_t len;
    unsigned char *ciphertext = encrypt_oracle(&len);
    if (padding_oracle(ciphertext, len)) {
        printf("Padding is good\n");
    } else {
        printf("Padding is bad\n");
    }

    free(key);
    return EXIT_SUCCESS;
}
