#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <stdbool.h>
#include <openssl/bn.h>

typedef struct {
    BIGNUM *public;
    BIGNUM *private;
    BIGNUM *modulus;
} RSA_Keypair;

typedef struct {
    BIGNUM *public;
    BIGNUM *private;
} DSA_Keypair;

typedef struct {
    BIGNUM *r;
    BIGNUM *s;
} DSA_Signature;

void *checked_malloc(const size_t len);
void *checked_calloc(const size_t nmemb, const size_t size);
void *checked_realloc(void *ptr, const size_t len);
void print_n_chars(const unsigned char *str, const size_t len);

unsigned char *hex_encode(const unsigned char *buffer, const size_t len);
unsigned char *hex_decode(const unsigned char *buffer, const size_t len);
unsigned char *base_64_encode(const unsigned char *buffer, const size_t len);
unsigned char *base_64_decode(const unsigned char *buffer, const size_t len);
unsigned char *xor_buffer(const unsigned char *left, const unsigned char *right, const size_t len);
unsigned long plaintext_frequency(const unsigned char *input, const size_t len);
unsigned long hamming_distance(const unsigned char *first, const unsigned char *second, const size_t len);
bool detect_ecb(const unsigned char *cipher, const size_t len);
unsigned char *pkcs7_pad(const unsigned char *mesg, const size_t mesg_len, const size_t padded_len);
unsigned long get_padded_length(const size_t len, const size_t padded_len);
bool validate_pkcs7_padding(const unsigned char *mesg, const size_t len);
unsigned char *aes_128_ecb_encrypt(const unsigned char *buffer, const size_t len, const unsigned char *key, size_t *cipher_len);
unsigned char *aes_128_ecb_decrypt(const unsigned char *buffer, const size_t len, const unsigned char *key, size_t *plaintext_len);
unsigned char *aes_128_cbc_encrypt(const unsigned char *buffer, const size_t len, const unsigned char *key, const unsigned char *iv, size_t *cipher_len);
unsigned char *aes_128_cbc_decrypt(const unsigned char *buffer, const size_t len, const unsigned char *key, const unsigned char *iv, size_t *plaintext_len);
unsigned char *aes_128_ctr_encrypt(const unsigned char *buffer, const size_t len, const unsigned char *key, const unsigned long long nonce);
unsigned char *aes_128_ctr_decrypt(const unsigned char *buffer, const size_t len, const unsigned char *key, const unsigned long long nonce);
unsigned char *generate_random_aes_key(void);
unsigned char *sha1_hash(const unsigned char *mesg, const size_t len);
unsigned char *sha256_hash(const unsigned char *mesg, const size_t len);
unsigned char *hmac_sha256(const unsigned char *mesg, const size_t mesg_len, const unsigned char *key, const size_t key_len);
BIGNUM *hex_to_bignum(const char *str);

const RSA_Keypair *generate_rsa_keys(const BIGNUM *exponent, const unsigned long bits);
void rsa_keypair_free(const RSA_Keypair *key_pair);
BIGNUM *rsa_encrypt(const BIGNUM *message, const BIGNUM *e, const BIGNUM *modulus);
BIGNUM *rsa_decrypt(const BIGNUM *message, const BIGNUM *d, const BIGNUM *modulus);

const DSA_Keypair *generate_dsa_keys(const BIGNUM *p, const BIGNUM *q, const BIGNUM *g);
void dsa_keypair_free(const DSA_Keypair *key_pair);
const DSA_Signature *dsa_sign(const unsigned char *message, const size_t len, const BIGNUM *p, const BIGNUM *q, const BIGNUM *g, const DSA_Keypair *key_pair);
bool dsa_verify(const unsigned char *message, const size_t len, const DSA_Signature *signature, const BIGNUM *p, const BIGNUM *q, const BIGNUM *g);

#endif
