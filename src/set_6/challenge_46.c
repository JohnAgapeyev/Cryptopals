#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include "../common.h"

bool parity_oracle(BIGNUM *ciphertext, const RSA_Keypair *keys) {
    BIGNUM *plaintext = rsa_decrypt(ciphertext, keys->private, keys->modulus);
    bool rtn = BN_is_odd(plaintext);
    BN_free(plaintext);
    return !rtn;
}

void decrypt_message(const BIGNUM *ciphertext, BIGNUM *lower, BIGNUM *upper) {
    long counter = 0;
    BN_CTX *ctx = BN_CTX_new();
    while (BN_cmp(lower, upper) < 0) {

    }
    BN_CTX_free(ctx);
}

int main(void) {
    const char *e_str = "65537";
    BIGNUM *e = hex_to_bignum(e_str);
    const RSA_Keypair *key_pair = generate_rsa_keys(e, 1024);

    const char *message = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";
    unsigned char *decoded_message = base_64_decode(message, strlen(message));
    BIGNUM *m = hex_to_bignum((const char *) decoded_message);

    BIGNUM *ciphertext = rsa_encrypt(m, key_pair->public, key_pair->modulus);

    BN_CTX *ctx = BN_CTX_new();




    BN_free(e);
    free(decoded_message);
    BN_free(m);
    BN_free(ciphertext);

    BN_CTX_free(ctx);

    rsa_keypair_free(key_pair);
    return EXIT_SUCCESS;
}
