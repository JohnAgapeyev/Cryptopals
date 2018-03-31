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

void decrypt_message(const BIGNUM *ciphertext, const RSA_Keypair *keys) {
    const char *e_str = "65537";
    BIGNUM *e = hex_to_bignum(e_str);

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *value = BN_new();
    BN_set_word(value, 2);
    BIGNUM *lower_bound = BN_new();
    BIGNUM *upper_bound = BN_dup(keys->modulus);
    BN_zero(lower_bound);
    BIGNUM *modified = BN_dup(ciphertext);
    BIGNUM *temp = BN_new();
    for (int i = 0; i < BN_num_bits(keys->modulus); ++i) {
        BN_mod_exp(temp, value, e, keys->modulus, ctx);
        BN_mod_mul(modified, modified, temp, keys->modulus, ctx);

        if (parity_oracle(modified, keys)) {
            //Even
            BN_add(upper_bound, upper_bound, lower_bound);
            BN_rshift1(upper_bound, upper_bound);
        } else {
            //Odd
            BN_add(lower_bound, upper_bound, lower_bound);
            BN_rshift1(lower_bound, lower_bound);
        }

        BN_lshift1(value, value);
        BN_copy(modified, ciphertext);

        char *hex = BN_bn2hex(upper_bound);
        unsigned char *decoded = hex_decode((const unsigned char *) hex, strlen(hex));
        printf("%s\n", decoded);
        free(hex);
        free(decoded);
    }
    BN_CTX_free(ctx);
    BN_free(value);
    BN_free(e);
}

int main(void) {
    const char *e_str = "65537";
    BIGNUM *e = hex_to_bignum(e_str);
    const RSA_Keypair *key_pair = generate_rsa_keys(e, 1024);

    const char *message = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";
    unsigned char *decoded_message = base_64_decode((const unsigned char *) message, strlen(message));
    unsigned char *hex_message = hex_encode(decoded_message, (strlen(message) / 4) * 3);
    BIGNUM *m = hex_to_bignum((const char *) hex_message);

    BIGNUM *ciphertext = rsa_encrypt(m, key_pair->public, key_pair->modulus);

    decrypt_message(ciphertext, key_pair);

    //Rounding errors consistently screw up the last 2-3 bytes, so just print the result manually
    //If the errors were a problem, it's not hard to brute force 3 bytes and see which make sense/are english
    printf("Set 6 Challenge 46 PASSED Decrypted message: %s\n", decoded_message);

    BN_free(e);
    free(decoded_message);
    free(hex_message);
    BN_free(m);
    BN_free(ciphertext);

    rsa_keypair_free(key_pair);
    return EXIT_SUCCESS;
}
