#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../common.h"

unsigned char *key = NULL;

const char *unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

unsigned char *encrypt_oracle(const unsigned char *mesg, const size_t len, size_t *out_len) {
    if (key == NULL) {
        key = generate_random_aes_key();
    }

    unsigned char *decoded_unknown = base_64_decode((const unsigned char *) unknown, strlen(unknown));
    size_t decoded_len = ((strlen(unknown) / 4) * 3);

    unsigned char plaintext[len + decoded_len];
    memcpy(plaintext, mesg, len);
    memcpy(plaintext + len, decoded_unknown, decoded_len);

    unsigned char *padded = pkcs7_pad(plaintext, len + decoded_len, 16);
    unsigned char *rtn = aes_128_ecb_encrypt(padded, (((len + decoded_len) / 16) + 1) * 16, key, out_len);
    free(padded);
    free(decoded_unknown);
    return rtn;
}

long detect_block_size(void) {
    size_t cipher_len;

    for (int i = 2; i <= 32; ++i) {
        unsigned char message[i * 2];
        memset(message, 'a', i * 2);

        unsigned char *ciphertext = encrypt_oracle(message, strlen((const char *) message), &cipher_len);

        for (size_t j = 0; j < (cipher_len / i); ++j) {
            for (size_t k = 0; k < (cipher_len / i); ++k) {
                if (j == k) {
                    continue;
                }
                if (memcmp(ciphertext + (j * i), ciphertext + (k * i), i) == 0) {
                    return i;
                }
            }
        }
        free(ciphertext);
    }
    return -1;
}

char leak_byte(const unsigned char *prev_leak, const size_t pos, size_t block_size) {
    if (pos >= block_size) {
        //Use multiple blocks if pos is greater than 1 block size
        block_size *= (pos / block_size) + 1;
    }

    unsigned char dictionary[256][block_size];
    for (int i = 0; i < 256; ++i) {
        unsigned char input[block_size];

        //printf("%zu\n", block_size - pos - 2);
        memset(input, 'a', block_size - pos - 1);

        for (size_t j = 0; j < pos; ++j) {
            input[block_size - pos + j - 1] = prev_leak[j];
        }
        //printf("%zu\n", block_size - 1);
        input[block_size - 1] = i;

        //printf("Dictionary filling: ");
        //print_n_chars(input, block_size);

        unsigned char *tmp = encrypt_oracle(input, block_size, NULL);
        memcpy(dictionary[i], tmp, block_size);

        free(tmp);
    }

    unsigned char input[block_size - 1];
    memset(input, 'a', block_size - 1);
    for (size_t j = 0; j < pos; ++j) {
        input[block_size - pos + j - 1] = prev_leak[j];
    }

    //printf("Chosen input: ");
    //print_n_chars(input, block_size);

    unsigned char *byte_leak = encrypt_oracle(input, block_size - pos - 1, NULL);
    for (int i = 0; i < 256; ++i) {
#if 1
        if (memcmp(byte_leak, dictionary[i], block_size) == 0) {
            //printf("Byte leaked as %c\n", i);
            free(byte_leak);
            return i;
        }
#else
        if (block_size > 16) {
            const size_t offset = (((block_size / 16) - 1) * 16);
            if (memcmp(byte_leak + offset, dictionary[i] + offset, 16) == 0) {
                //printf("Byte leaked as %c\n", i);
                free(byte_leak);
                return i;
            }
        } else {
            if (memcmp(byte_leak, dictionary[i], 16) == 0) {
                //printf("Byte leaked as %c\n", i);
                free(byte_leak);
                return i;
            }
        }
#endif
    }
    free(byte_leak);
    //printf("No match\n");
    return -1;
}

int main(void) {
    unsigned char message[100];
    memset(message, 'a', 100);

    size_t cipher_len;
    unsigned char *ciphertext = encrypt_oracle(message, 100, &cipher_len);

    long block_size = detect_block_size();
    if (block_size == -1) {
        fprintf(stderr, "We couldn't find the block size!\n");
        abort();
    }

    if (!detect_ecb(ciphertext, cipher_len)) {
        fprintf(stderr, "How did this even happen?\n");
        abort();
    }
    free(ciphertext);

#if 0
    unsigned char dictionary[256][block_size];
    for (int i = 0; i < 256; ++i) {
        unsigned char input[block_size];
        memset(input, 'a', block_size - 1);
        input[block_size - 1] = i;

        unsigned char *tmp = encrypt_oracle(input, block_size, NULL);
        memcpy(dictionary[i], tmp, block_size);

        free(tmp);
    }

    unsigned char input[block_size - 1];
    memset(input, 'a', block_size - 1);

    unsigned char *byte_leak = encrypt_oracle(input, block_size - 1, NULL);

    unsigned char prev = 0;
    for (int i = 0; i < 256; ++i) {
        if (memcmp(byte_leak, dictionary[i], block_size) == 0) {
            printf("First byte leaked as %c\n", i);
            prev = i;
        }
    }

    for (int i = 0; i < 256; ++i) {
        unsigned char input[block_size];
        memset(input, 'a', block_size - 2);
        input[block_size - 2] = prev;
        input[block_size - 1] = i;

        unsigned char *tmp = encrypt_oracle(input, block_size, NULL);
        memcpy(dictionary[i], tmp, block_size);

        free(tmp);
    }

    unsigned char input_1[block_size - 2];
    memset(input_1, 'a', block_size - 2);
    input_1[block_size - 2] = prev;

    byte_leak = encrypt_oracle(input_1, block_size - 2, NULL);
    for (int i = 0; i < 256; ++i) {
        if (memcmp(byte_leak, dictionary[i], block_size) == 0) {
            printf("Second byte leaked as %c\n", i);
        }
    }
#endif
    unsigned char x = ' ';
    size_t len = 0;
    unsigned char *empty = encrypt_oracle(&x, 0, &len);
    unsigned char *test = aes_128_ecb_decrypt(empty, len, key, NULL);

    unsigned char prev_leak[len];
    for (int i = 0; i < len; ++i) {
        if (i > 140) {
            printf(" ");
        }
        prev_leak[i] = leak_byte(prev_leak, i, block_size);
    }

    printf("\n\n\n\n\n\n\nOutput: ");
    print_n_chars(prev_leak, len);

    printf("Last padding byte: %02x\n", prev_leak[len - 1]);


    free(key);
    return EXIT_SUCCESS;
}
