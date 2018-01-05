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

BIGNUM *dsa_key_recovery(const unsigned char *message, const size_t len, const BIGNUM *k) {
    unsigned char *hash = sha1_hash(message, len);
    unsigned char *hex_str = hex_encode(hash, 20);
    BIGNUM *bn_hash = hex_to_bignum((const char *) hex_str);

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *r_inverse = BN_new();
    //Apparently these parameters are decimal numbers not hex, which threw me for a loop
    BN_dec2bn(&r_inverse, "519334352112663596410160066327650448249099314077");

    BIGNUM *s = BN_new();
    BN_dec2bn(&s, "857042759984254168557880549501802188789837994940");

    BIGNUM *x = BN_new();
    BN_mul(x, s, k, ctx);

    BN_sub(x, x, bn_hash);

    BN_mod_mul(x, x, r_inverse, q, ctx);

    BN_CTX_free(ctx);

    free(hash);
    free(hex_str);

    BN_free(bn_hash);
    BN_free(r_inverse);
    BN_free(s);

    return x;
}

int main(void) {
    init_globals();
    const char *message = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";

    const char *hash_str = "0954edd5e0afe5542a4adf012611a91912a3ec16";

    BIGNUM *bn_i = BN_new();
    for (unsigned int i = 0; i <= (1 << 17); ++i) {
        BN_set_word(bn_i, i);
        BIGNUM *x = dsa_key_recovery((const unsigned char *) message, strlen(message), bn_i);
        char *x_str = BN_bn2hex(x);

        for (size_t j = 0; j < strlen(x_str); ++j) {
            x_str[j] = tolower(x_str[j]);
        }

        unsigned char *hash = sha1_hash((unsigned char *) x_str, strlen(x_str));
        unsigned char *tmp_str = hex_encode(hash, 20);

        if (memcmp(tmp_str, hash_str, 20) == 0) {
            printf("Set 6 Challenge 43 Recovered secret key: %d\n", i);

            BN_free(x);
            free(x_str);
            free(hash);
            free(tmp_str);
            goto cleanup;
        }
        BN_free(x);
        free(x_str);
        free(hash);
        free(tmp_str);
    }
    printf("Set 6 Challenge 43 FAILED Unable to recover secret key\n");
cleanup:
    BN_free(bn_i);
    free_globals();
    return EXIT_SUCCESS;
}
