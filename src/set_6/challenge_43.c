#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <openssl/bn.h>
#include "../common.h"

const char *p_str = "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1";
const char *q_str = "f4f47f05794b256174bba6e9b396a7707e563c5b";
const char *g_str = "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291";

BIGNUM *p;
BIGNUM *q;
BIGNUM *g;

void init_globals(void) {
    p = hex_to_bignum(p_str);
    q = hex_to_bignum(q_str);
    g = hex_to_bignum(g_str);
}

void free_globals(void) {
    BN_free(p);
    BN_free(q);
    BN_free(g);
}

BIGNUM *dsa_key_recovery(const unsigned char *message, const size_t len, const BIGNUM *k, const DSA_Signature *signature) {
    unsigned char *hash = sha1_hash(message, len);
    unsigned char *hex_str = hex_encode(hash, 20);
    BIGNUM *bn_hash = hex_to_bignum((const char *) hex_str);

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *r_inverse = BN_mod_inverse(NULL, signature->r, q, ctx);

    BIGNUM *x = BN_new();
    BN_mod_mul(x, signature->s, k, q, ctx);
    BN_mod_sub(x, x, bn_hash, q, ctx);
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
    const char *message = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";

    const char *r_str = "548099063082341131477253921760299949438196259240";
    const char *s_str = "857042759984254168557880549501802188789837994940";

    BIGNUM *r = hex_to_bignum(r_str);
    BIGNUM *s = hex_to_bignum(s_str);

    const char *y_str = "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17";
    BIGNUM *y = hex_to_bignum(y_str);

    DSA_Signature sig;
    sig.r = r;
    sig.s = s;

    const char *hash_str = "0954edd5e0afe5542a4adf012611a91912a3ec16";
    //unsigned char *hash_result = hex_decode((const unsigned char *) hash_str, strlen(hash_str));

    printf("%s\n%s\n%s\n%s\n", r_str, s_str, y_str, hash_str);

    BIGNUM *bn_i = BN_new();
    for (unsigned int i = 0; i <= (1ul << 31); ++i) {
        BN_set_word(bn_i, i);
        BIGNUM *x = dsa_key_recovery((const unsigned char *) message, strlen(message), bn_i, &sig);
        char *x_str = BN_bn2hex(x);

        printf("%s\n", x_str);

        for (size_t j = 0; j < strlen(x_str); ++j) {
            x_str[j] = tolower(x_str[j]);
        }
        printf("%s\n", x_str);
        //printf("%s\n", hash_str);

#if 0
        BN_CTX *ctx = BN_CTX_new();
        DSA_Keypair k;
        k.private = x;
        k.public = BN_new();
        BN_mod_exp(k.public, g, x, p, ctx);
        const DSA_Signature *temp_sig = dsa_sign((const unsigned char *) message, strlen(message), p, q, g, &k);

        BN_CTX_free(ctx);
        BN_free(k.public);

        if (BN_cmp(temp_sig->r, r) == 0) {
            printf("We did it!\n");
        }
        if (BN_cmp(temp_sig->s, s) == 0) {
            printf("We did it!\n");
        }

        char *test_r = BN_bn2hex(temp_sig->r);
        char *test_s = BN_bn2hex(temp_sig->s);

        printf("%s\n%s\n", test_r, test_s);
#else
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *test = BN_new();
        BN_mod_exp(test, g, bn_i, p, ctx);

        if (BN_cmp(y, test) == 0) {
            printf("Woot!\n");
            abort();
        }

        char *test_str = BN_bn2hex(test);
        for (size_t j = 0; j < strlen(test_str); ++j) {
            test_str[j] = tolower(test_str[j]);
        }

        printf("%s\n", test_str);

        free(test_str);

        BN_CTX_free(ctx);
        BN_free(test);
#endif

        if (BN_cmp(y, bn_i) == 0) {
            printf("Woot!\n");
            abort();
        }
        if (BN_cmp(y, x) == 0) {
            printf("Woot!\n");
            abort();
        }

        unsigned char *hash = sha1_hash((unsigned char *) x_str, strlen(x_str));
        unsigned char *tmp_str = hex_encode(hash, 20);
        for (size_t j = 0; j < 40; ++j) {
            printf("%c", tmp_str[j]);
        }
        printf("\n");
        for (size_t j = 0; j < 40; ++j) {
            printf("%02x", tmp_str[j]);
        }
        printf("\n");
        for (size_t j = 0; j < 20; ++j) {
            printf("%02x", hash[j]);
        }
        printf("\n\n");
        if (memcmp(tmp_str, hash_str, 20) == 0) {
            fprintf(stderr, "Got it!\n");
            abort();

            BN_free(x);
            free(x_str);
            free(hash);
            free(tmp_str);
            break;
        }
        BN_free(x);
        free(x_str);
        free(hash);
            free(tmp_str);
    }
    printf("Loop done!\n");

    free_globals();
    return EXIT_SUCCESS;
}
