#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../common.h"

const char *q_str = "f4f47f05794b256174bba6e9b396a7707e563c5b";
const char *p_str = "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1";

BIGNUM *q;
BIGNUM *p;
BIGNUM *g;

void init_globals(void) {
    q = hex_to_bignum(q_str);
    p = hex_to_bignum(p_str);
    g = BN_new();
}

void free_globals(void) {
    BN_free(q);
    BN_free(p);
    BN_free(g);
}

DSA_Signature *bad_dsa_sign(const unsigned char *message, const size_t len, const BIGNUM *p, const BIGNUM *q, const BIGNUM *y) {
    BN_CTX *ctx = BN_CTX_new();
    unsigned char *hash = sha1_hash(message, len);
    unsigned char *hex_str = hex_encode(hash, 20);
    BIGNUM *bn_hash = hex_to_bignum((const char *) hex_str);

    BIGNUM *z = BN_new();
    //Arbitrary number
    BN_set_word(z, 3700);
    BIGNUM *z_inverse = BN_mod_inverse(NULL, z, q, ctx);

    DSA_Signature *out = checked_malloc(sizeof(DSA_Signature));
    out->r = BN_new();
    out->s = BN_new();

    //r = (y ** z mod p) mod q
    BN_mod_exp(out->r, y, z, p, ctx);
    BN_mod(out->r, out->r, q, ctx);

    BN_mod_mul(out->s, out->r, z_inverse, q, ctx);

    BN_CTX_free(ctx);
    free(hash);
    free(hex_str);
    BN_free(bn_hash);
    BN_free(z);
    BN_free(z_inverse);

    return out;
}

/**
 * I don't use 0 mod p for g because of the implementation spec
 * https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Signing
 * My code generates an infinite loop retrying to sign the message
 * The key is generating parameter r which is (g^k mod p) mod q
 * With g == 0, the error check if r is zero will always be hit, resulting in the forever loop
 * I understand that if r is zero, the private key is never added into the signature
 * Therefore the signature can be verified for any message.
 * I'm choosing to ignore it because adding an error return would only complicate what is supposed to be
 * a learning experience.
 */
int main(void) {
    const unsigned char *message_1 = (const unsigned char *) "Hello, world";
    const unsigned char *message_2 = (const unsigned char *) "Goodbye, world";
    init_globals();

    BN_add(g, p, BN_value_one());

    const DSA_Keypair *keys = generate_dsa_keys(p, q, g);

    const DSA_Signature *sig = dsa_sign(message_1, strlen((char *) message_1), p, q, g, keys);

    const DSA_Signature *bad_sig = bad_dsa_sign(message_2, strlen((char *) message_2), p, q, keys->public);

    if (!dsa_verify(message_1, strlen((char *) message_1), sig, p, q, g)) {
        printf("Set 6 Challenge 44 FAILED Unable to verify standard signature\n");
        goto cleanup;
    }
    if (!dsa_verify(message_2, strlen((char *) message_2), bad_sig, p, q, g)) {
        printf("Set 6 Challenge 44 FAILED Unable to verify forged signature\n");
        goto cleanup;
    }

    printf("Set 6 Challenge 45 PASSED Valid and forged signatures both verified correctly\n");

cleanup:
    free((DSA_Signature *) sig);
    free((DSA_Signature *) bad_sig);
    dsa_keypair_free(keys);
    free_globals();
    return EXIT_SUCCESS;
}
