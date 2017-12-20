#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <stdbool.h>

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
unsigned char *generate_random_aes_key(void);

#endif
