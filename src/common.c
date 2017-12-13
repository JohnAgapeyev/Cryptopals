#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "common.h"

static void *checked_malloc(const size_t len);
static void *checked_calloc(const size_t nmemb, const size_t size);
static void *checked_realloc(void *ptr, const size_t len);

static const char *hex_values = "0123456789abcdef";

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

unsigned char *hex_encode(const unsigned char *buffer, const size_t len) {
    unsigned char *out = checked_malloc(len * 2);
    for (size_t i = 0; i < len; ++i) {
        snprintf(out + (i * 2), 2, "%02x", buffer[i]);
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
        out[i] = ((unsigned char) (memchr(hex_values, buffer[i * 2], strlen(hex_values)) - (void *) hex_values)) * 16;
        out[i] += (unsigned char) (memchr(hex_values, buffer[i * 2 + 1], strlen(hex_values)) - (void *) hex_values);
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

