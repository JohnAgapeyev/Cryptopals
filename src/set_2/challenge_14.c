#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include "../common.h"

unsigned char *key = NULL;
unsigned char *prefix = NULL;
unsigned short prefix_len;
const char *unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

unsigned char *encrypt_oracle(const unsigned char *mesg, const size_t len, size_t *out_len) {
    if (key == NULL) {
        key = generate_random_aes_key();
    }
    if (prefix == NULL) {
        prefix_len = rand() % USHRT_MAX;
        prefix = checked_malloc(prefix_len);
        for (size_t i = 0; i < prefix_len; ++i) {
            prefix[i] = rand();
        }
    }

    unsigned char *decoded_unknown = base_64_decode((const unsigned char *) unknown, strlen(unknown));
    size_t decoded_len = ((strlen(unknown) / 4) * 3);

    unsigned char plaintext[prefix_len + len + decoded_len];
    memcpy(plaintext, prefix, prefix_len);
    memcpy(plaintext + prefix_len, mesg, len);
    memcpy(plaintext + prefix_len + len, decoded_unknown, decoded_len);

    unsigned char *padded = pkcs7_pad(plaintext, prefix_len + len + decoded_len, 16);
    unsigned char *rtn = aes_128_ecb_encrypt(padded, (((prefix_len + len + decoded_len) / 16) + 1) * 16, key, out_len);
    free(padded);
    free(decoded_unknown);
    return rtn;
}

long detect_block_size(void) {
    size_t cipher_len = 0;

    for (int i = 2; i <= 32; ++i) {
        unsigned char message[i * 10];
        memset(message, 'a', i * 10);

        unsigned char *ciphertext = encrypt_oracle(message, i * 10, &cipher_len);

        for (size_t j = 0; j < (cipher_len / i) - 2; ++j) {
            if (memcmp(ciphertext + (j * i), ciphertext + ((j + 1) * i), i) == 0
                    && memcmp(ciphertext + (j * i), ciphertext + ((j + 2) * i), i) == 0) {
                free(ciphertext);
                return i;
            }
        }
        free(ciphertext);
    }
    return -1;
}

//Returns the index of the first block affected by the input
//Essentially, the padded length of the random prefix
long detect_offset(const long block_size) {
    unsigned char message[block_size * 10];
    memset(message, 'a', block_size * 10);

    size_t cipher_len = 0;
    unsigned char *ciphertext = encrypt_oracle(message, block_size * 10, &cipher_len);

    for (unsigned long i = 0; i < (cipher_len / block_size) - 2; ++i) {
        if (memcmp(ciphertext + (i * block_size), ciphertext + ((i + 1) * block_size), block_size) == 0
                && memcmp(ciphertext + (i * block_size), ciphertext + ((i + 2) * block_size), block_size) == 0) {
            free(ciphertext);
            return i * block_size;
        }
    }
    free(ciphertext);
    return -1;
}

char leak_byte(const unsigned char *prev_leak, const size_t pos, size_t block_size, const size_t offset, const size_t remainder) {
    if (pos >= block_size) {
        //Use multiple blocks if pos is greater than 1 block size
        block_size *= (pos / block_size) + 1;
    }

    unsigned char dictionary[256][block_size];
    for (int i = 0; i < 256; ++i) {
        unsigned char input[block_size + remainder];

        memset(input, 'a', block_size + remainder - pos - 1);
        for (size_t j = 0; j < pos; ++j) {
            input[block_size + remainder - pos + j - 1] = prev_leak[j];
        }
        input[block_size + remainder - 1] = i;

        unsigned char *tmp = encrypt_oracle(input, block_size + remainder, NULL);
        memcpy(dictionary[i], tmp + offset + (16 - remainder), block_size);

        free(tmp);
    }

    unsigned char input[block_size + remainder - 1];
    memset(input, 'a', block_size + remainder - 1);
    for (size_t j = 0; j < pos; ++j) {
        input[block_size + remainder - pos + j - 1] = prev_leak[j];
    }

    size_t out_len;
    unsigned char *byte_leak = encrypt_oracle(input, block_size + remainder - pos - 1, &out_len);

    for (int i = 0; i < 256; ++i) {
        /*
         * Compare the output with the dictionary
         * memcmp the block size, except when the requested position causes the block size
         * to be larger than the ciphertext length, in which case, subtract a block
         */
        if ((out_len - offset - (16 - remainder)) > block_size + remainder) {
            if (memcmp(byte_leak + offset + (16 - remainder), dictionary[i], block_size) == 0) {
                free(byte_leak);
                return i;
            }
        } else {
            if (memcmp(byte_leak + offset + (16 - remainder), dictionary[i], block_size - 16) == 0) {
                free(byte_leak);
                return i;
            }
        }
    }
    free(byte_leak);
    return -1;
}

int main(void) {
    srand(time(NULL));
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

    long offset = detect_offset(block_size);
    if (offset == -1) {
        fprintf(stderr, "We couldn't find the block offset!\n");
        abort();
    }

    //Unused char to prevent UB by passing nullptr to memset in encrypt_oracle
    unsigned char x = ' ';
    size_t len = 0;
    //Encrypt with no added string to get the plain ciphertext len
    unsigned char *empty = encrypt_oracle(&x, 0, &len);
    free(empty);

    //Remove block offset from length
    len -= offset;

    unsigned long max_score = 0;
    int index = 0;
    for (int h = 0; h <= block_size; ++h) {
        unsigned char prev_leak[len];
        memset(prev_leak, 0, len);
        for (size_t i = 0; i < len; ++i) {
            prev_leak[i] = leak_byte(prev_leak, i, block_size, offset - block_size, h);
        }

        unsigned long score = plaintext_frequency(prev_leak, len);
        if (score > max_score) {
            max_score = score;
            index = h;
        }
    }

    //If the block offset is not equal to the prefix length, then the length will be short by
    //an amount equal to the remainder.
    //So I add the remainder here to compensate for that
    len += index;

    unsigned char prev_leak[len];
    for (size_t i = 0; i < len; ++i) {
        prev_leak[i] = leak_byte(prev_leak, i, block_size, offset - block_size, index);
    }

    printf("Set 2 Challenge 14 Decrypted output: ");
    print_n_chars(prev_leak, len);

    free(key);
    free(prefix);
    return EXIT_SUCCESS;
}
