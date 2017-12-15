#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "common.h"

static const char *hex_values = "0123456789abcdef";
static const char *common_letters = "etoinshrdlu ";

#define openssl_error() \
    do {\
        fprintf(stderr, "OpenSSL error %s at %s, line %d in function %s\n", ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__, __func__); \
        exit(EXIT_FAILURE);\
    } while(0)

void *checked_malloc(const size_t len) {
    void *out = malloc(len);
    if (out == NULL) {
        abort();
    }
    return out;
}

void *checked_calloc(const size_t nmemb, const size_t size) {
    void *out = calloc(nmemb, size);
    if (out == NULL) {
        abort();
    }
    return out;
}

void *checked_realloc(void *ptr, const size_t len) {
    void *out = realloc(ptr, len);
    if (out == NULL) {
        abort();
    }
    return out;
}

void print_n_chars(const unsigned char *str, const size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%c\n", str[i]);
    }
    printf("\n");
}

unsigned char *hex_encode(const unsigned char *buffer, const size_t len) {
    unsigned char *out = checked_malloc((len * 2) + 1);
    for (size_t i = 0; i < len; ++i) {
        snprintf((char *) out + (i * 2), 3, "%02x", buffer[i]);
    }
    return out;
}

unsigned char *hex_decode(const unsigned char *buffer, const size_t len) {
    if (len & 1) {
        fprintf(stderr, "Length must be divisible by 2\n");
        abort();
    }
    unsigned char *out = checked_malloc(len / 2);

    for (size_t i = 0; i < len / 2; ++i) {
        out[i] = ((unsigned char) ((const char *) memchr(hex_values, buffer[i * 2], strlen(hex_values)) - hex_values)) * 16;
        out[i] += (unsigned char) ((const char *) memchr(hex_values, buffer[i * 2 + 1], strlen(hex_values)) - hex_values);
    }
    return out;
}

unsigned char *base_64_encode(const unsigned char *buffer, const size_t len) {
    unsigned char *out = checked_malloc((((len / 3) + 1) * 4) + 1);

    EVP_EncodeBlock(out, buffer, len);
    return out;
}

unsigned char *base_64_decode(const unsigned char *buffer, const size_t len) {
    unsigned char *out = checked_malloc((len / 4) * 3);
    if (out == NULL) {
        abort();
    }
    EVP_DecodeBlock(out, buffer, len);
    return out;
}

unsigned char *xor_buffer(const unsigned char *left, const unsigned char *right, const size_t len) {
    unsigned char *out = checked_malloc(len);
    for (size_t i = 0; i < len; ++i) {
        out[i] = left[i] ^ right[i];
    }
    return out;
}

unsigned long plaintext_frequency(const unsigned char *input, const size_t len) {
    unsigned long score = 0;
    for (size_t i = 0; i < strlen(common_letters); ++i) {
        for (size_t j = 0; j < len; ++j) {
            if (input[j] == common_letters[i]) {
                ++score;
            }
        }
    }
    return score;
}

unsigned long hamming_distance(const unsigned char *first, const unsigned char *second, const size_t len) {
    unsigned long count = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char diff = first[i] ^ second[i];
        while (diff > 0) {
            if ((diff & 1) == 1) {
                ++count;
            }
            diff >>= 1;
        }
    }
    return count;
}

unsigned char *aes_128_ecb_encrypt(const unsigned char *buffer, const size_t len, const unsigned char *key, size_t *cipher_len) {
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        openssl_error();
    }

    unsigned char *ciphertext = checked_malloc(len + EVP_CIPHER_block_size(EVP_aes_128_ecb()));

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        openssl_error();
    }

    int tmp_len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &tmp_len, buffer, len) != 1) {
        openssl_error();
    }

    int ciphertext_len = tmp_len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + tmp_len, &tmp_len) != 1) {
        openssl_error();
    }
    ciphertext_len += tmp_len;

    *cipher_len = ciphertext_len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

unsigned char *aes_128_ecb_decrypt(const unsigned char *buffer, const size_t len, const unsigned char *key, size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        openssl_error();
    }

    unsigned char *plaintext = checked_malloc(len);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        openssl_error();
    }

    int tmp_len;
    if (EVP_DecryptUpdate(ctx, plaintext, &tmp_len, buffer, len) != 1) {
        openssl_error();
    }

    int plain_len = tmp_len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + tmp_len, &tmp_len) != 1) {
        openssl_error();
    }
    plain_len += tmp_len;

    *plaintext_len = plain_len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

