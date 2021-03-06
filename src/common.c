#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include "common.h"

static const char *hex_values = "0123456789abcdef";
static const char *common_letters = "etaoinshrdlucmfwyp ";

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
    out[len * 2] = '\0';
    return out;
}



unsigned char *hex_decode(const unsigned char *buffer, const size_t len) {
    if (len & 1) {
        fprintf(stderr, "Length must be divisible by 2\n");
        abort();
    }
    unsigned char *out = checked_malloc(len / 2);

    for (size_t i = 0; i < len / 2; ++i) {
        out[i] = ((unsigned char) ((const char *) memchr(hex_values, tolower(buffer[i * 2]), strlen(hex_values)) - hex_values)) * 16;
        out[i] += (unsigned char) ((const char *) memchr(hex_values, tolower(buffer[i * 2 + 1]), strlen(hex_values)) - hex_values);
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
            if (tolower(input[j]) == common_letters[i]) {
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
    const size_t block_size = EVP_CIPHER_block_size(EVP_aes_128_ecb());

    unsigned char *plaintext = pkcs7_pad(buffer, len, block_size);
    size_t plain_len = get_padded_length(len, block_size);

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
    free(plaintext);
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

unsigned char *aes_128_ctr_encrypt(const unsigned char *buffer, const size_t len, const unsigned char *key, const unsigned long long nonce) {
    unsigned long long counter = 0;

    unsigned char input[sizeof(unsigned long long) * 2];
    memcpy(input, &nonce, sizeof(unsigned long long));
    memcpy(input + sizeof(unsigned long long), &counter, sizeof(unsigned long long));

    unsigned char *out = checked_malloc(len);

    for (size_t i = 0; i < (len / 16); ++i) {
        unsigned char *output = aes_128_ecb_encrypt(input, sizeof(unsigned long long) * 2, key, NULL);
        unsigned char *cipher_block = xor_buffer(output, buffer + (i * 16), 16);

        memcpy(out + (i * 16), cipher_block, 16);

        free(output);
        free(cipher_block);

        ++counter;

        memcpy(input + sizeof(unsigned long long), &counter, sizeof(unsigned long long));
    }
    unsigned char *output = aes_128_ecb_encrypt(input, sizeof(unsigned long long) * 2, key, NULL);
    unsigned char *cipher_block = xor_buffer(output, buffer + ((len / 16) * 16), len - ((len / 16) * 16));

    memcpy(out + ((len / 16) * 16), cipher_block, len - ((len / 16) * 16));

    free(output);
    free(cipher_block);

    return out;
}

unsigned char *aes_128_ctr_decrypt(const unsigned char *buffer, const size_t len, const unsigned char *key, const unsigned long long nonce) {
    return aes_128_ctr_encrypt(buffer, len, key, nonce);
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
    if (padding_length == 0) {
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

unsigned char *sha1_hash(const unsigned char *mesg, const size_t len) {
    SHA_CTX ctx;

    if (SHA1_Init(&ctx) != 1) {
        openssl_error();
    }

    if (SHA1_Update(&ctx, mesg, len) != 1) {
        openssl_error();
    }

    unsigned char *out = checked_malloc(20);

    if (SHA1_Final(out, &ctx) != 1) {
        openssl_error();
    }

    return out;
}

unsigned char *sha256_hash(const unsigned char *mesg, const size_t len) {
    SHA256_CTX ctx;

    if (SHA256_Init(&ctx) != 1) {
        openssl_error();
    }

    if (SHA256_Update(&ctx, mesg, len) != 1) {
        openssl_error();
    }

    unsigned char *out = checked_malloc(32);

    if (SHA256_Final(out, &ctx) != 1) {
        openssl_error();
    }

    return out;
}

unsigned char *hmac_sha256(const unsigned char *mesg, const size_t mesg_len, const unsigned char *key, const size_t key_len) {
    unsigned char padded_key[32];
    if (key_len <= 32) {
        memset(padded_key, 0, 32);
        memcpy(padded_key, key, key_len);
    } else {
        unsigned char *hashed_key = sha256_hash(key, key_len);
        memcpy(padded_key, hashed_key, 32);
        free(hashed_key);
    }

    unsigned char outer[32];
    unsigned char inner[32];
    memset(outer, 0x5c, 32);
    memset(inner, 0x36, 32);

    unsigned char *inner_xor = xor_buffer(inner, padded_key, 32);
    unsigned char *outer_xor = xor_buffer(outer, padded_key, 32);

    unsigned char inner_input[32 + mesg_len];
    memcpy(inner_input, inner_xor, 32);
    memcpy(inner_input + 32, mesg, mesg_len);

    unsigned char *inner_hash = sha256_hash(inner_input, 32 + mesg_len);

    unsigned char final_input[64];
    memcpy(final_input, outer_xor, 32);
    memcpy(final_input + 32, inner_hash, 32);

    unsigned char *rtn = sha256_hash(final_input, 64);

    free(inner_xor);
    free(outer_xor);
    free(inner_hash);

    return rtn;
}

BIGNUM *hex_to_bignum(const char *str) {
    BIGNUM *out = NULL;
    BN_hex2bn(&out, str);
    return out;
}

const RSA_Keypair *generate_rsa_keys(const BIGNUM *exponent, const unsigned long bits) {
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();

    BN_generate_prime_ex(p, bits / 2, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(q, bits / 2, 1, NULL, NULL, NULL);

    BIGNUM *one = BN_new();
    BN_one(one);

    BIGNUM *temp_p = BN_new();
    BN_sub(temp_p, p, one);

    BIGNUM *temp_q = BN_new();
    BN_sub(temp_q, q, one);

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *et = BN_new();
    BN_mul(et, temp_p, temp_q, ctx);

    BIGNUM *d = BN_mod_inverse(NULL, exponent, et, ctx);

    BIGNUM *N = BN_new();
    BN_mul(N, p, q, ctx);

    RSA_Keypair *key_pair = checked_malloc(sizeof(RSA_Keypair));

    key_pair->public = BN_dup(exponent);
    key_pair->private = d;
    key_pair->modulus = N;

    BN_clear_free(p);
    BN_clear_free(q);
    BN_free(one);
    BN_clear_free(temp_p);
    BN_clear_free(temp_q);

    BN_CTX_free(ctx);

    BN_clear_free(et);

    return key_pair;
}

void rsa_keypair_free(const RSA_Keypair *key_pair) {
    BN_free(key_pair->public);
    BN_clear_free(key_pair->private);
    BN_free(key_pair->modulus);
    free((void *) key_pair);
}

BIGNUM *rsa_encrypt(const BIGNUM *message, const BIGNUM *e, const BIGNUM *modulus) {
    BIGNUM *out = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(out, message, e, modulus, ctx);
    BN_CTX_free(ctx);
    return out;
}

BIGNUM *rsa_decrypt(const BIGNUM *message, const BIGNUM *d, const BIGNUM *modulus) {
    return rsa_encrypt(message, d, modulus);
}

const DSA_Keypair *generate_dsa_keys(const BIGNUM *p, const BIGNUM *q, const BIGNUM *g) {
    DSA_Keypair *keys = checked_malloc(sizeof(DSA_Keypair));
    keys->private = BN_new();
    keys->public = BN_new();

    BN_rand_range(keys->private, q);
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(keys->public, g, keys->private, p, ctx);
    BN_CTX_free(ctx);

    return keys;
}

void dsa_keypair_free(const DSA_Keypair *key_pair) {
    BN_clear_free(key_pair->private);
    BN_clear_free(key_pair->public);
    free((void *) key_pair);
}

const DSA_Signature *dsa_sign(const unsigned char *message, const size_t len, const BIGNUM *p, const BIGNUM *q, const BIGNUM *g, const DSA_Keypair *key_pair) {
    BIGNUM *zero = BN_new();
    BN_zero(zero);
    BIGNUM *k = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    unsigned char *hash = sha1_hash(message, len);
    unsigned char *hex_str = hex_encode(hash, 20);
    BIGNUM *bn_hash = hex_to_bignum((const char *) hex_str);
new_k:
    BN_rand_range(k, q);
    if (BN_cmp(k, zero) == 0) {
        goto new_k;
    }
    BN_mod_exp(r, g, k, p, ctx);
    BN_mod(r, r, q, ctx);
    if (BN_cmp(r, zero) == 0) {
        goto new_k;
    }

    BN_mod_mul(s, key_pair->private, r, q, ctx);
    BN_mod_add(s, s, bn_hash, q, ctx);

    BIGNUM *k_inverse = BN_mod_inverse(NULL, k, q, ctx);
    BN_mod_mul(s, s, k_inverse, q, ctx);

    if (BN_cmp(s, zero) == 0) {
        BN_free(k_inverse);
        goto new_k;
    }

    DSA_Signature *out = checked_malloc(sizeof(DSA_Signature));
    out->r = r;
    out->s = s;

    BN_free(zero);
    BN_free(k);
    BN_CTX_free(ctx);
    free(hash);
    free(hex_str);
    BN_free(bn_hash);
    BN_free(k_inverse);

    return out;
}

bool dsa_verify(const unsigned char *message, const size_t len, const DSA_Signature *signature, const BIGNUM *p, const BIGNUM *q, const BIGNUM *g) {
    BIGNUM *zero = BN_new();
    BN_zero(zero);

    if (BN_cmp(signature->r, zero) != 1) {
        BN_free(zero);
        return false;
    }
    if (BN_cmp(signature->r, q) != -1) {
        BN_free(zero);
        return false;
    }
    if (BN_cmp(signature->s, zero) != 1) {
        BN_free(zero);
        return false;
    }
    if (BN_cmp(signature->s, q) != -1) {
        BN_free(zero);
        return false;
    }

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *w = BN_mod_inverse(NULL, signature->s, q, ctx);

    unsigned char *hash = sha1_hash(message, len);
    unsigned char *hex_str = hex_encode(hash, 20);
    BIGNUM *bn_hash = hex_to_bignum((const char *) hex_str);

    BIGNUM *u_1 = BN_new();
    BN_mod_mul(u_1, bn_hash, w, q, ctx);

    BIGNUM *u_2 = BN_new();
    BN_mod_mul(u_2, signature->r, w, q, ctx);

    BIGNUM *term_1 = BN_new();
    BN_mod_exp(term_1, g, u_1, p, ctx);

    BIGNUM *term_2 = BN_new();
    BN_mod_exp(term_2, g, u_2, p, ctx);

    BIGNUM *v = BN_new();
    BN_mod_mul(v, term_1, term_2, p, ctx);
    BN_mod(v, v, q, ctx);

    BN_free(zero);
    BN_CTX_free(ctx);
    BN_free(w);
    BN_free(bn_hash);
    BN_free(u_1);
    BN_free(u_2);
    BN_free(term_1);
    BN_free(term_2);
    free(hash);
    free(hex_str);

    if (BN_cmp(v, signature->r) == 0) {
        BN_free(v);
        return true;
    } else {
        BN_free(v);
        return false;
    }
}
