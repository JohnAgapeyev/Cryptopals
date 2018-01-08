#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../common.h"

const char *y_str = "2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821";
const char *q_str = "f4f47f05794b256174bba6e9b396a7707e563c5b";
const char *p_str = "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1";
const char *g_str = "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291";

BIGNUM *q;
BIGNUM *y;
BIGNUM *p;
BIGNUM *g;

void init_globals(void) {
    y = hex_to_bignum(y_str);
    q = hex_to_bignum(q_str);
    p = hex_to_bignum(p_str);
    g = hex_to_bignum(g_str);
}

void free_globals(void) {
    BN_free(y);
    BN_free(q);
    BN_free(p);
    BN_free(g);
}

BIGNUM *get_k(const BIGNUM *m1, const BIGNUM *m2, const BIGNUM *s1, const BIGNUM *s2) {
    BIGNUM *m_diff = BN_new();
    BIGNUM *s_diff = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_mod_sub(m_diff, m1, m2, q, ctx);
    BN_mod_sub(s_diff, s1, s2, q, ctx);

    BN_mod_inverse(s_diff, s_diff, q, ctx);

    BN_mod_mul(m_diff, m_diff, s_diff, q, ctx);

    BN_CTX_free(ctx);
    BN_free(s_diff);

    return m_diff;
}

BIGNUM *dsa_key_recovery(const unsigned char *message, const size_t len, const BIGNUM *k, const BIGNUM *r, const BIGNUM *s) {
    unsigned char *hash = sha1_hash(message, len);
    unsigned char *hex_str = hex_encode(hash, 20);
    BIGNUM *bn_hash = hex_to_bignum((const char *) hex_str);

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *r_inverse = BN_mod_inverse(NULL, r, q, ctx);

    BIGNUM *x = BN_new();
    BN_mul(x, s, k, ctx);

    BN_sub(x, x, bn_hash);

    BN_mod_mul(x, x, r_inverse, q, ctx);

    BN_CTX_free(ctx);

    free(hash);
    free(hex_str);

    BN_free(bn_hash);
    BN_free(r_inverse);

    return x;
}

int main(void) {
    init_globals();
    FILE *fp = fopen("44.txt", "rb");
    if (fp == NULL) {
        fprintf(stderr, "44.txt could not be found\n");
        return EXIT_FAILURE;
    }

    unsigned char messages[11][1024];
    unsigned char sig_s[11][1024];
    unsigned char sig_r[11][1024];
    unsigned char hashes[11][1024];

    memset(messages, 0, 11 * 1024);
    memset(sig_s, 0, 11 * 1024);
    memset(sig_r, 0, 11 * 1024);
    memset(hashes, 0, 11 * 1024);

    char input[1024];
    size_t index = 0;
    while (fgets(input, 1023, fp)) {
        unsigned char key[1024];
        unsigned char value[1024];
        memset(key, 0, 1024);
        memset(value, 0, 1024);

        unsigned char *colon_index = memchr(input, ':', 1024);
        if (colon_index == NULL) {
            fprintf(stderr, "Every line should contain a colon character\n");
            abort();
        }

        memcpy(key, input, (colon_index - (unsigned char *) input));
        memcpy(value, colon_index + 1, strlen(input + (colon_index - (unsigned char *) input)));

        //Strip newline from value
        value[strlen((char *) value) - 1] = '\0';
        memmove(value, value + 1, strlen((char *) value));

        switch(key[0]) {
            case 'r':
                memcpy(sig_r[index / 4], value, strlen((char *) value));
                break;
            case 's':
                memcpy(sig_s[index / 4], value, strlen((char *) value));
                break;
            case 'm':
                if (key[1] == 's') {
                    memcpy(messages[index / 4], value, strlen((char *) value));
                } else {
                    memcpy(hashes[index / 4], value, strlen((char *) value));
                }
                break;
        }
        ++index;
    }
    fclose(fp);

    BIGNUM *zero = BN_new();
    BN_zero(zero);

    const char *hex_result = "ca8f6f7c66fa362d40760d135b763eb8527d3d52";

    for (size_t i = 0; i < 9; ++i) {
        for (size_t j = i + 1; j < 10; ++j) {
            BIGNUM *m_1 = hex_to_bignum((const char *) hashes[i]);
            BIGNUM *m_2 = hex_to_bignum((const char *) hashes[j]);

            BIGNUM *s_1 = NULL;
            BN_dec2bn(&s_1, (const char *) sig_s[i]);
            BIGNUM *s_2 = NULL;
            BN_dec2bn(&s_2, (const char *) sig_s[j]);

            BIGNUM *r_1 = NULL;
            BN_dec2bn(&r_1, (const char *) sig_r[i]);
            BIGNUM *r_2 = NULL;
            BN_dec2bn(&r_2, (const char *) sig_r[j]);

            BIGNUM *k = get_k(m_1, m_2, s_1, s_2);
            if (BN_cmp(k, zero) == 0) {
                BN_free(m_1);
                BN_free(m_2);
                BN_free(s_1);
                BN_free(s_2);
                BN_free(r_1);
                BN_free(r_2);
                BN_free(k);
                continue;
            }

            BIGNUM *one = dsa_key_recovery((const unsigned char *) messages[i], strlen((const char *) messages[i]), k, r_1, s_1);
            BIGNUM *two = dsa_key_recovery((const unsigned char *) messages[j], strlen((const char *) messages[j]), k, r_2, s_2);

            BN_free(m_1);
            BN_free(m_2);
            BN_free(s_1);
            BN_free(s_2);
            BN_free(r_1);
            BN_free(r_2);
            BN_free(k);

            if (BN_cmp(one, two) == 0) {

                char *secret_str = BN_bn2hex(one);
                for (size_t h = 0; h < strlen(secret_str); ++h) {
                    secret_str[h] = tolower(secret_str[h]);
                }
                unsigned char *secret_hash = sha1_hash((const unsigned char *) secret_str, strlen((char *) secret_str));
                unsigned char *hex = hex_encode(secret_hash, 20);

                BN_free(one);
                BN_free(two);

                free(secret_hash);

                if (memcmp(hex_result, hex, 40) == 0) {
                    printf("Set 6 Challenge 44 Secret key found: %s\n", secret_str);
                    free(hex);
                    free(secret_str);
                    goto done;
                } else {
                    printf("Set 6 Challenge 44 FAILED Secret key hash did not match known result\n");
                    free(hex);
                    free(secret_str);
                    goto done;
                }

            }
            BN_free(one);
            BN_free(two);
        }
    }
    printf("Set 6 Challenge 44 FAILED Unable to find duplicate nonce\n");

done:
    BN_free(zero);
    free_globals();
    return EXIT_SUCCESS;
}
