#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <openssl/bn.h>
#include "../common.h"

const char *g_str = "2";
const char *k_str = "3";
const char *N_str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff";
const char *email = "testing@test.com";
const char *password = "Hello world!";

BIGNUM *g;
BIGNUM *k;
BIGNUM *N;
uint64_t salt;

void init_globals(void) {
    N = hex_to_bignum(N_str);
    g = hex_to_bignum(g_str);
    k = hex_to_bignum(k_str);
    salt = rand() % ULLONG_MAX;
}

//Perform SRP given a client A value, and return the HMAC
unsigned char *SRP(BIGNUM *A) {
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

    BN_clear_free(x);
    free(xH);
    free(hex_xH);

    //v has been generated, x and xH have been freed

    BIGNUM *a = BN_new();
    BN_rand(a, BN_num_bits(N), 0, 0);
    BN_mod(a, a, N, ctx);

    //BIGNUM *A = BN_new();
    //BN_mod_exp(A, g, a, N, ctx);

    BIGNUM *b = BN_new();
    BN_rand(b, BN_num_bits(N), 0, 0);
    BN_mod(b, b, N, ctx);

    //tmp is equal to k * v
    BIGNUM *tmp = BN_new();
    BN_mul(tmp, k, v, ctx);

    BIGNUM *B = BN_new();
    BN_mod_exp(B, g, b, N, ctx);

    BN_add(B, B, tmp);

    BN_nnmod(B, B, N, ctx);

    //B is now equal to kv + g**b % N

    char *A_str = BN_bn2hex(A);
    char *B_str = BN_bn2hex(B);

    char *AB = checked_malloc(strlen(A_str) + strlen(B_str));
    memcpy(AB, A_str, strlen(A_str));
    memcpy(AB + strlen(A_str), B_str, strlen(B_str));

    unsigned char *uH = sha256_hash((const unsigned char *) AB, strlen(A_str) + strlen(B_str));

    unsigned char *hex_uH = hex_encode(uH, 32);

    char u_input[65];
    memcpy(u_input, hex_uH, 64);
    u_input[64] = '\0';

    BIGNUM *u = hex_to_bignum(u_input);

    //u and uH have now been calculated

    xH = sha256_hash(salted_password, strlen(password) + sizeof(uint64_t));
    hex_xH = hex_encode(xH, 32);

    memcpy(x_input, hex_xH, 64);
    x_input[64] = '\0';

    x = hex_to_bignum(x_input);

    BIGNUM *client_S = BN_new();

    BIGNUM *base = BN_new();
    BN_mod_exp(base, g, x, N, ctx);
    BN_mul(base, base, k, ctx);
    BN_sub(base, B, base);

    //base is now equal to (B-k*g**x)

    BIGNUM *expo = BN_new();
    BN_mul(expo, u, x, ctx);
    BN_add(expo, expo, a);

    //expo is now equal to a + u * x

    BN_mod_exp(client_S, base, expo, N, ctx);

    char *client_s_str = BN_bn2hex(client_S);
    unsigned char *client_key = sha256_hash((const unsigned char *) client_s_str, strlen(client_s_str));

    //Client has now generated K on their end

    BIGNUM *server_base = BN_new();
    BN_mod_exp(server_base, v, u, N, ctx);
    BN_mul(server_base, server_base, A, ctx);
    //server_base is now equal to A * v**u

    BIGNUM *server_s = BN_new();
    BN_mod_exp(server_s, server_base, b, N, ctx);

    //server_s is now equal to (A * v**u) ** b % N

    char *server_s_str = BN_bn2hex(server_s);
    unsigned char *server_key = sha256_hash((const unsigned char *) server_s_str, strlen(server_s_str));

    unsigned char *client_hmac = hmac_sha256((unsigned char *) &salt, sizeof(uint64_t), client_key, 32);

    unsigned char *server_hmac = hmac_sha256((unsigned char *) &salt, sizeof(uint64_t), server_key, 32);

    BN_free(g);
    BN_free(N);
    BN_free(k);

    BN_free(v);

    BN_CTX_free(ctx);

    BN_free(a);
    BN_free(A);
    BN_free(b);
    BN_free(B);
    BN_free(tmp);

    OPENSSL_free(A_str);
    OPENSSL_free(B_str);
    free(AB);

    free(uH);
    free(hex_uH);
    BN_free(u);

    BN_free(x);
    free(xH);
    free(hex_xH);

    BN_free(client_S);
    BN_free(base);
    BN_free(expo);
    OPENSSL_free(client_s_str);

    free(client_key);

    BN_free(server_base);
    BN_free(server_s);

    OPENSSL_free(server_s_str);
    free(server_key);

    free(client_hmac);

    return server_hmac;
}

int main(void) {
    init_globals();

    BIGNUM *zero = BN_new();
    //Sending an A value of zero results in a client key equal to sha256(0)
    //Sending a multiple of N also resultes in zero due to modular reduction
    BN_zero(zero);

    unsigned char *server_hmac = SRP(zero);
    unsigned char *forged_key = sha256_hash((const unsigned char *) "0", 1);
    unsigned char *forged_client = hmac_sha256((unsigned char *) &salt, sizeof(uint64_t), forged_key, 32);

    if (CRYPTO_memcmp(server_hmac, forged_client, 32) == 0) {
        printf("Set 5 challenge 37 HMAC forged successfully\n");
    } else {
        printf("Set 5 challenge 37 FAILED HMAC failed to validate\n");
    }

    free(server_hmac);
    free(forged_key);
    free(forged_client);

    return EXIT_SUCCESS;
}
