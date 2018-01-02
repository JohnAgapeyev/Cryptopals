#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/bn.h>
#include "../common.h"

int main(void) {
    //65537 as the exponent
    const char *e_str = "10001";
    BIGNUM *e = hex_to_bignum(e_str);

    const RSA_Keypair *key_pair = generate_rsa_keys(e, 2048);

    const char *message = "This is a test of RSA";
    unsigned char *hex_message = hex_encode((const unsigned char *) message, strlen(message));

    printf("Set 5 Challenge 39\n");
    printf("Initial message: %s\n", message);

    BIGNUM *m = hex_to_bignum((const char *) hex_message);

    BIGNUM *ciphertext = rsa_encrypt(m, key_pair->public, key_pair->modulus);

    char *cipher_hex = BN_bn2hex(ciphertext);
    printf("Ciphertext: %s\n", cipher_hex);

    BIGNUM *plaintext = rsa_decrypt(ciphertext, key_pair->private, key_pair->modulus);

    char *plain_hex = BN_bn2hex(plaintext);

    unsigned char *decrypted_message = hex_decode((const unsigned char *) plain_hex, strlen(message) * 2);

    printf("Decrypted message: ");
    print_n_chars(decrypted_message, strlen(message));

    rsa_keypair_free(key_pair);

    BN_free(e);
    BN_free(m);
    BN_free(ciphertext);
    BN_free(plaintext);

    free(hex_message);
    free(cipher_hex);
    free(plain_hex);
    free(decrypted_message);

    return EXIT_SUCCESS;
}
