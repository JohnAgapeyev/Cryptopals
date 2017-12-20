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
        printf("%c", str[i]);
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
    memset(ciphertext, 0, len + EVP_CIPHER_block_size(EVP_aes_128_ecb()));

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        openssl_error();
    }

    //Disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int tmp_len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &tmp_len, buffer, len) != 1) {
        openssl_error();
    }

    int ciphertext_len = tmp_len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + tmp_len, &tmp_len) != 1) {
        openssl_error();
    }
    ciphertext_len += tmp_len;

    if (cipher_len) {
        *cipher_len = ciphertext_len;
    }

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

    //Disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int tmp_len;
    if (EVP_DecryptUpdate(ctx, plaintext, &tmp_len, buffer, len) != 1) {
        openssl_error();
    }

    int plain_len = tmp_len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + tmp_len, &tmp_len) != 1) {
        openssl_error();
    }
    plain_len += tmp_len;

    if (plaintext_len) {
        *plaintext_len = plain_len;
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

unsigned char *aes_128_cbc_encrypt(const unsigned char *buffer, const size_t len, const unsigned char *key, const unsigned char *iv, size_t *cipher_len) {
    const unsigned char *plaintext = NULL;
    size_t plain_len;

    const size_t block_size = EVP_CIPHER_block_size(EVP_aes_128_ecb());

    if (len % block_size != 0) {
        //Message needs to be padded
        plaintext = pkcs7_pad(buffer, len, block_size);
        plain_len = get_padded_length(len, block_size);
    } else {
        plaintext = buffer;
        plain_len = len;
    }
    unsigned char *ciphertext = checked_malloc(plain_len);
    if (cipher_len) {
        *cipher_len = plain_len;
    }

    unsigned char prev[block_size];
    memcpy(prev, iv, block_size);

    unsigned char block[block_size];
    for (size_t i = 0; i < plain_len / block_size; ++i) {
        memcpy(block, plaintext + (i * block_size), block_size);

        unsigned char *xor_plain = xor_buffer(block, prev, block_size);

        unsigned char *cipher_block = aes_128_ecb_encrypt(xor_plain, block_size, key, NULL);

        //Save the encrypted block to the result buffer
        memcpy(ciphertext + (i * block_size), cipher_block, block_size);

        //Save the encrypted block to prev
        memcpy(prev, cipher_block, block_size);

        free(xor_plain);
        free(cipher_block);
    }
    return ciphertext;
}

unsigned char *aes_128_cbc_decrypt(const unsigned char *buffer, const size_t len, const unsigned char *key, const unsigned char *iv, size_t *plaintext_len) {
    const size_t block_size = EVP_CIPHER_block_size(EVP_aes_128_ecb());
    if (len % block_size != 0) {
        fprintf(stderr, "Ciphertext is not a correctly padded length!\n");
        abort();
    }
    unsigned char *plaintext = checked_malloc(len);

    size_t plain_block_size;
    if (plaintext_len) {
        *plaintext_len = 0;
    }

    unsigned char prev[block_size];
    memcpy(prev, iv, block_size);

    unsigned char block[block_size];
    for (size_t i = 0; i < len / block_size; ++i) {
        memcpy(block, buffer + (i * block_size), block_size);

        unsigned char *decrypted_block = aes_128_ecb_decrypt(block, block_size, key, &plain_block_size);
        if (plaintext_len) {
            *plaintext_len += plain_block_size;
        }

        unsigned char *plain_block = xor_buffer(decrypted_block, prev, plain_block_size);

        //Save plaintext to outgoing buffer
        memcpy(plaintext + (i * block_size), plain_block, plain_block_size);

        //Save current ciphertext block to prev
        memcpy(prev, block, plain_block_size);

        free(decrypted_block);
        free(plain_block);
    }
    return plaintext;
}

bool detect_ecb(const unsigned char *cipher, const size_t len) {
    for (size_t i = 0; i < (len / 16); ++i) {
        for (size_t j = 0; j < (len / 16); ++j) {
            if (j == i) {
                continue;
            }
            if (memcmp(cipher + (i * 16), cipher + (j * 16), 16) == 0) {
                return true;
            }
        }
    }
    return false;
}

unsigned char *pkcs7_pad(const unsigned char *mesg, const size_t mesg_len, const size_t padded_len) {
    const size_t total_padded_len = get_padded_length(mesg_len, padded_len);
    unsigned char *padded_mesg = checked_malloc(total_padded_len);

    memcpy(padded_mesg, mesg, mesg_len);
    memset(padded_mesg + mesg_len, total_padded_len - mesg_len, total_padded_len - mesg_len);

    return padded_mesg;
}

unsigned long get_padded_length(const size_t len, const size_t padded_len) {
    return ((len / padded_len) + 1) * padded_len;
}

bool validate_pkcs7_padding(const unsigned char *mesg, const size_t len) {
    unsigned char padding_length = mesg[len - 1];
    if (padding_length > len) {
        return false;
    }
    for (size_t i = 1; i <= padding_length; ++i) {
        if (mesg[len - i] != padding_length) {
            return false;
        }
    }
    return true;
}

unsigned char *generate_random_aes_key(void) {
    unsigned char *out = checked_malloc(EVP_CIPHER_block_size(EVP_aes_128_ecb()));
    for (int i = 0; i < EVP_CIPHER_block_size(EVP_aes_128_ecb()); ++i) {
        //Doesn't need to be cryptographically secure, just random
        out[i] = rand();
    }
    return out;
}
