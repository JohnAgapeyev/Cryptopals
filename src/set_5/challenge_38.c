#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <openssl/bn.h>
#include "../common.h"

const char *g_str = "2";
const char *N_str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff";

//Any word in /usr/dict/words will work
const char *password = "caricature";

BIGNUM *g;
BIGNUM *N;

void init_globals(void) {
    N = hex_to_bignum(N_str);
    g = hex_to_bignum(g_str);
}

unsigned char *simplified_SRP(BIGNUM **A_out, BIGNUM *b, BIGNUM *B, BIGNUM *u, uint64_t salt) {
    unsigned char salted_password[strlen(password) + sizeof(uint64_t)];
    memcpy(salted_password, &salt, sizeof(uint64_t));
    memcpy(salted_password + sizeof(uint64_t), password, strlen(password));

    unsigned char *xH = sha256_hash(salted_password, strlen(password) + sizeof(uint64_t));
    unsigned char *hex_xH = hex_encode(xH, 32);

    char x_input[65];
    memcpy(x_input, hex_xH, 64);
    x_input[64] = '\0';

    BIGNUM *x = hex_to_bignum(x_input);

    BIGNUM *v = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(v, g, x, N, ctx);

    free(xH);
    free(hex_xH);
    BN_free(x);

    BIGNUM *a = BN_new();
    BN_rand(a, BN_num_bits(N), 0, 0);
    BN_mod(a, a, N, ctx);

    BIGNUM *A = BN_new();
    BN_mod_exp(A, g, a, N, ctx);

    BN_copy(*A_out, A);

    xH = sha256_hash(salted_password, strlen(password) + sizeof(uint64_t));
    hex_xH = hex_encode(xH, 32);

    memcpy(x_input, hex_xH, 64);
    x_input[64] = '\0';

    x = hex_to_bignum(x_input);

    BIGNUM *S = BN_new();
    BIGNUM *expo = BN_new();

    BN_mul(expo, u, x, ctx);
    BN_add(expo, a, expo);

    BN_mod_exp(S, B, expo, N, ctx);

    char *s_str = BN_bn2hex(S);
    unsigned char *client_key = sha256_hash((unsigned char *) s_str, strlen(s_str));

    free(s_str);

    BN_zero(S);

    BIGNUM *base = BN_new();

    BN_mod_exp(base, v, u, N, ctx);
    BN_mul(base, base, A, ctx);

    BN_mod_exp(S, base, b, N, ctx);

    s_str = BN_bn2hex(S);
    unsigned char *server_key = sha256_hash((unsigned char *) s_str, strlen(s_str));

    unsigned char *client_hmac = hmac_sha256((unsigned char *) &salt, sizeof(uint64_t), client_key, 32);

    free(xH);
    free(hex_xH);
    BN_free(x);

    BN_free(v);
    BN_free(a);
    BN_free(A);

    BN_free(S);
    BN_free(expo);

    free(s_str);

    BN_free(base);

    BN_CTX_free(ctx);

    free(server_key);
    free(client_key);

    return client_hmac;
}

int main(void) {
    init_globals();

    FILE *fp = fopen("/usr/share/dict/words", "r");
    if (fp == NULL) {
        fprintf(stderr, "/usr/share/dict/words could not be found\n");
        exit(EXIT_FAILURE);
    }

    BIGNUM *A = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *B = BN_new();
    BIGNUM *u = BN_new();
    //Set b to 1
    BN_one(b);
    //If b is 1, B is equal to g
    BN_copy(B, g);
    //Set u to 1
    BN_one(u);

    uint64_t salt = 0;

    BIGNUM *S = BN_new();
    BIGNUM *v = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    bool found_pass = false;

    char input[1024];
    while (fgets(input, 1023, fp)) {
        unsigned char *hmac_target = simplified_SRP(&A, b, B, u, salt);

        char salted_password[strlen(input) - 1 + sizeof(uint64_t)];
        memcpy(salted_password, &salt, sizeof(uint64_t));
        memcpy(salted_password + sizeof(uint64_t), input, strlen(input) - 1);

        unsigned char *test_hash = sha256_hash((unsigned char *) salted_password, strlen(input) - 1 + sizeof(uint64_t));
        unsigned char *hex_xH = hex_encode(test_hash, 32);

        char x_input[65];
        memcpy(x_input, hex_xH, 64);
        x_input[64] = '\0';

        BIGNUM *x = hex_to_bignum(x_input);

        BN_mod_exp(v, g, x, N, ctx);

        //Since u and b are set to 1, this simplifies the math here
        BN_mul(S, A, v, ctx);
        BN_nnmod(S, S, N, ctx);

        char *s_str = BN_bn2hex(S);

        unsigned char *test_key = sha256_hash((unsigned char *) s_str, strlen(s_str));
        unsigned char *test_hmac = hmac_sha256((unsigned char *) &salt, sizeof(uint64_t), test_key, 32);

        free(test_hash);
        free(hex_xH);
        BN_free(x);
        free(s_str);
        free(test_key);

        if (memcmp(test_hmac, hmac_target, 32) == 0) {
            found_pass = true;
            free(test_hmac);
            free(hmac_target);
            break;
        }
        free(test_hmac);
        free(hmac_target);
    }
    if (found_pass) {
        printf("Set 5 Challenge 38 Recovered password: %s\n", password);
    } else {
        printf("Set 5 Challenge 38 FAILED Failed to recover password\n");
    }

    BN_free(A);
    BN_free(S);
    BN_free(v);

    BN_free(g);
    BN_free(N);

    BN_CTX_free(ctx);

    fclose(fp);

    return EXIT_SUCCESS;
}
