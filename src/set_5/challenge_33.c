#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <openssl/bn.h>
#include "../common.h"

void diffie_helman(void) {
    const char *p_str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff";

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = hex_to_bignum(p_str);
    const char *g_str = "2";

    BIGNUM *g = hex_to_bignum(g_str);

    BIGNUM *a = BN_new();
    BN_rand(a, BN_num_bits(p), 0, 0);
    BN_mod(a, a, p, ctx);

    BIGNUM *b = BN_new();
    BN_rand(b, BN_num_bits(p), 0, 0);
    BN_mod(b, b, p, ctx);

    BIGNUM *A = BN_new();
    BN_mod_exp(A, g, a, p, ctx);

    BIGNUM *B = BN_new();
    BN_mod_exp(B, g, b, p, ctx);

    BIGNUM *first_s = BN_new();
    BN_mod_exp(first_s, A, b, p, ctx);

    BIGNUM *second_s = BN_new();
    BN_mod_exp(second_s, B, a, p, ctx);

    if (BN_cmp(first_s, second_s) == 0) {
        printf("Set 5 Challenge 33 Keys exchanged successfully!\n");
    } else {
        printf("Set 5 Challenge 33 Key exchange FAILED!\n");
    }

    BN_CTX_free(ctx);

    BN_free(p);
    BN_free(g);
    BN_free(a);
    BN_free(b);
    BN_free(A);
    BN_free(B);
    BN_free(first_s);
    BN_free(second_s);
}

int main(void) {
    diffie_helman();
    return EXIT_SUCCESS;
}
