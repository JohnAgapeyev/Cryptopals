#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <openssl/bn.h>
#include "../common.h"

unsigned char *diffie_helman(void) {
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
    //A has been substituted with p here
    BN_mod_exp(first_s, p, b, p, ctx);

    BIGNUM *second_s = BN_new();
    //B has been substituted with p here
    BN_mod_exp(second_s, p, a, p, ctx);

    if (BN_cmp(first_s, second_s) != 0) {
        printf("Key exchange failed!\n");
        abort();
    }

    //Keys have been exchanged
    //With MITM substitution, the resulting key is == 0

    //Hash the key
    unsigned char *hash = sha1_hash((const unsigned char *) BN_bn2hex(first_s), strlen(BN_bn2hex(first_s)));

    BN_CTX_free(ctx);

    BN_free(p);
    BN_free(g);
    BN_free(a);
    BN_free(b);
    BN_free(A);
    BN_free(B);
    BN_free(first_s);
    BN_free(second_s);

    return hash;
}

int main(void) {
    unsigned char *secret_key = diffie_helman();

    unsigned char *mitm_key = sha1_hash((const unsigned char *) "0", 1);

    const char *mesg = "Hello world!";

    unsigned char *iv = generate_random_aes_key();

    size_t cipher_len;
    unsigned char *ciphertext = aes_128_cbc_encrypt((const unsigned char *) mesg, strlen(mesg), secret_key, iv, &cipher_len);

    //Could append iv to simulate network packet, but I'll just use it normally to save effort since I know what the iv is

    unsigned char *plaintext = aes_128_cbc_decrypt(ciphertext, cipher_len, secret_key, iv, NULL);

    if (memcmp(mesg, (const char *) plaintext, strlen(mesg)) != 0) {
        printf("Basic decryption somehow failed!\n");
        abort();
    }

    unsigned char *mitm_plaintext = aes_128_cbc_decrypt(ciphertext, cipher_len, mitm_key, iv, NULL);
    if (memcmp(mesg, (const char *) mitm_plaintext, strlen(mesg)) != 0) {
        printf("MITM decryption was not successful!\n");
        abort();
    }

    printf("Set 5 Challenge 34 MITM decrypted without issues!\n");

    free(secret_key);
    free(mitm_key);
    free(iv);
    free(ciphertext);
    free(plaintext);
    free(mitm_plaintext);

    return EXIT_SUCCESS;
}
