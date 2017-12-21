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

    //size_t index = rand() % 10;
    size_t index = 1;
    printf("%zu\n", index);
    printf("%s\n", unknown_strings[index]);

    unsigned char *rtn = aes_128_cbc_encrypt(unknown_strings[index], strlen((const char *) unknown_strings[index]), key, iv, out_len);
    return rtn;
}

bool padding_oracle(const unsigned char *mesg, const size_t len) {
    size_t plain_len;
    unsigned char *plaintext = aes_128_cbc_decrypt(mesg, len, key, iv, &plain_len);

    //printf("Last byte: %02x\n", plaintext[plain_len - 1]);

    //print_n_chars(plaintext, plain_len);

#if 0
    for (size_t i = 0; i < plain_len; ++i) {
        printf("%02x", plaintext[i]);
    }
    printf("\n");
#endif

    bool rtn = validate_pkcs7_padding(plaintext, plain_len);
    free(plaintext);
    return rtn;
}

#if 1
unsigned char *decrypt_mesg(const unsigned char *mesg, const size_t len) {
    unsigned char *out = checked_malloc(len);
    memset(out, 0xff, len);

    unsigned char buffer[len];
    for (int i = len - 1; i >= 16; --i) {
    //int i = len - 1; {
        for (unsigned int j = 0; j < 256; ++j) {
            if (j == (len - i)) {
                continue;
            }
            memcpy(buffer, mesg, len);

            for (int k = len - 1; k > i; --k) {
                if (k < 16) {
                    printf("Woops\n");
                } else {
                    //buffer[k] = out[i + 1] ^ (len - i);
                    buffer[k - 16 - 0] ^= out[i + 1] ^ (len - i);
                }
            }

            if (i < 16) {
                printf("Bap\n");
            } else {
                //buffer[i] = buffer[i - 16] ^ j ^ (len - i);
                buffer[i - 16 - 0] ^= j ^ (len - i);
            }
            //buffer[len - 1] = j ^ 0x01;

            //printf("%02x\n", len - i);

            if (padding_oracle(buffer, len)) {
                out[i] = j;
                printf("%d\n", j);
                break;
            }
        }
        printf("Index %d\n", i);
    }
    return out;
#else
unsigned char decrypt_mesg(const unsigned char *mesg, const size_t len) {
    //printf("%zu\n\n\n", len);
    for (unsigned int j = 0; j < 256; ++j) {
        if (j == 1) {
            continue;
        }
        unsigned char buffer[len];
        memcpy(buffer, mesg, len);

        //buffer[47] = buffer[47] ^ j ^ 0x01;
        buffer[47] ^= j ^ 0x01;
        printf("Trying: %d\n", j);

        if (padding_oracle(buffer, len)) {
            printf("%d\n", j);
            return j;
        }
    }
    return -1;
#endif
}

int main(void) {
    //srand(time(NULL));
    fill_unknown();

    size_t len;
    unsigned char *ciphertext = encrypt_oracle(&len);
    //padding_oracle(ciphertext, len);
    //if (padding_oracle(ciphertext, len)) {
        //printf("Padding is good\n");
    //} else {
        //printf("Padding is bad\n");
    //}

    //unsigned char buffer[len];
    //memcpy(buffer, ciphertext, len);

    //buffer[47] = buffer[47] ^ j ^ 0x01;
    //buffer[47] = buffer[63] ^ 0x08 ^ 0x01;
    //buffer[47] = buffer[47] ^ 8 ^ 1;
    //buffer[47] ^= 8 ^ 1;

    //if (!padding_oracle(buffer, len)) {
        //abort();
    //}
    //printf("We're good\n");

    unsigned char *plaintext = decrypt_mesg(ciphertext, len);
    //printf("%c\n", decrypt_mesg(ciphertext, len));

    print_n_chars(plaintext, len);

    free(key);
    return EXIT_SUCCESS;
}
