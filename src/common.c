#include <stdlib.h>
#include <openssl/evp.h>
#include "common.h"

static void *checked_malloc(const size_t len);
static void *checked_calloc(const size_t nmemb, const size_t size);
static void *checked_realloc(void *ptr, const size_t len);

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

unsigned char *base_64_encode(const unsigned char *buffer, const size_t len) {
    unsigned char *out = checked_malloc(((len / 3) + 1) * 4);

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
    if (out == NULL) {
        abort();
    }

    for (size_t i = 0; i < len; ++i) {
        out[i] = left[i] ^ right[i];
    }
    return out;
}

