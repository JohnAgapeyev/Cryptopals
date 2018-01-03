#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include "../common.h"

int main(void) {
    const char *e_str = "3";
    BIGNUM *e = hex_to_bignum(e_str);
    const RSA_Keypair *key_pair = generate_rsa_keys(e, 2048);

    const char *message = "RSA really needs padding dontcha know?";
    unsigned char *hex_message = hex_encode((const unsigned char *) message, strlen(message));

    BIGNUM *m = hex_to_bignum((const char *) hex_message);

    BIGNUM *ciphertext = rsa_encrypt(m, key_pair->public, key_pair->modulus);

    //Q: How do we decrypt the ciphertext without knowing the private key or being able to decrypt the original message?
    //A: Abuse the homomorphic property of unpadded RSA by multiplying the ciphertext by a known value, then dividing the plaintext by it

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *S = BN_new();
random:
    BN_rand(S, 128, 0, 0);
    BN_mod(S, S, key_pair->modulus, ctx);

    if (BN_cmp(S, BN_value_one()) == 0) {
        goto random;
    }

    BIGNUM *modified_ciphertext = BN_new();

    BN_mod_exp(modified_ciphertext, S, key_pair->public, key_pair->modulus, ctx);
    BN_mod_mul(modified_ciphertext, modified_ciphertext, ciphertext, key_pair->modulus, ctx);

    BIGNUM *modified_plaintext = rsa_decrypt(modified_ciphertext, key_pair->private, key_pair->modulus);

    BIGNUM *S_inverse = BN_mod_inverse(NULL, S, key_pair->modulus, ctx);

    BIGNUM *plaintext = BN_new();

    BN_mod_mul(plaintext, modified_plaintext, S_inverse, key_pair->modulus, ctx);

    char *plain_str = BN_bn2hex(plaintext);
    unsigned char *recovered = hex_decode((const unsigned char *) plain_str, strlen(plain_str));

    printf("Set 6 Challenge 41 Decrypted message: ");
    print_n_chars(recovered, strlen(plain_str) / 2);

    BN_free(e);
    free(hex_message);
    BN_free(m);
    BN_free(ciphertext);

    BN_CTX_free(ctx);

    BN_free(S);

    BN_free(modified_ciphertext);
    BN_free(modified_plaintext);
    BN_free(S_inverse);
    BN_free(plaintext);

    free(plain_str);
    free(recovered);

    rsa_keypair_free(key_pair);
    return EXIT_SUCCESS;
}
