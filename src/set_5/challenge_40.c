#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/bn.h>
#include "../common.h"

/*
 * Calculates the nth root using Newton's method and the OpenSSL Bignum library
 */
BIGNUM *nth_root(BIGNUM *input, const unsigned long n) {
    int bit_count = BN_num_bits(input);

    int first_bit_index = -1;
    for (int i = bit_count; i > 0; --i) {
        if (BN_is_bit_set(input, i)) {
            first_bit_index = i;
            break;
        }
    }
    if (first_bit_index == -1) {
        return NULL;
    }

    BIGNUM *power_of_two = BN_new();
    BN_zero(power_of_two);
    BN_set_bit(power_of_two, first_bit_index);

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *x = BN_dup(power_of_two);
    BIGNUM *y = BN_new();

    BIGNUM *bn_n = BN_new();
    BN_set_word(bn_n, n);

    BIGNUM *n_minus_one = BN_new();
    BN_set_word(n_minus_one, n - 1);

    BIGNUM *temp_1 = BN_new();
    BIGNUM *temp_2 = BN_new();

    BIGNUM *rtn = BN_new();

    while (BN_cmp(x, BN_value_one()) == 1) {
        BN_exp(temp_1, x, n_minus_one, ctx);
        BN_div(temp_1, NULL, input, temp_1, ctx);

        BN_mul(temp_2, n_minus_one, x, ctx);

        BN_add(y, temp_1, temp_2);

        BN_div(y, NULL, y, bn_n, ctx);

        if (BN_cmp(y, x) != -1) {
            BN_copy(rtn, x);
            goto cleanup;
        }
        BN_copy(x, y);
    }
    BN_one(rtn);
cleanup:
    BN_free(power_of_two);
    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(y);
    BN_free(bn_n);
    BN_free(n_minus_one);
    BN_free(temp_1);
    BN_free(temp_2);
    return rtn;
}

int main(void) {
    const char *e_str = "3";
    BIGNUM *e = hex_to_bignum(e_str);

    const RSA_Keypair *key_pair_1 = generate_rsa_keys(e, 2048);
    const RSA_Keypair *key_pair_2 = generate_rsa_keys(e, 2048);
    const RSA_Keypair *key_pair_3 = generate_rsa_keys(e, 2048);

    const char *message = "This is why you shouldn't use e=3 in RSA";
    unsigned char *hex_message = hex_encode((const unsigned char *) message, strlen(message));

    BIGNUM *m = hex_to_bignum((const char *) hex_message);

    BIGNUM *ciphertext_1 = rsa_encrypt(m, key_pair_1->public, key_pair_1->modulus);
    BIGNUM *ciphertext_2 = rsa_encrypt(m, key_pair_2->public, key_pair_2->modulus);
    BIGNUM *ciphertext_3 = rsa_encrypt(m, key_pair_3->public, key_pair_3->modulus);

    BN_CTX *ctx = BN_CTX_new();

    //The following blocks calculate the CRT equivalent of the 3 ciphertexts and their moduli
    BIGNUM *m_s_0 = BN_new();
    BN_mul(m_s_0, key_pair_2->modulus, key_pair_3->modulus, ctx);

    BIGNUM *m_s_1 = BN_new();
    BN_mul(m_s_1, key_pair_1->modulus, key_pair_3->modulus, ctx);

    BIGNUM *m_s_2 = BN_new();
    BN_mul(m_s_2, key_pair_1->modulus, key_pair_2->modulus, ctx);

    BIGNUM *inverse_1 = BN_mod_inverse(NULL, m_s_0, key_pair_1->modulus, ctx);

    BIGNUM *inverse_2 = BN_mod_inverse(NULL, m_s_1, key_pair_2->modulus, ctx);

    BIGNUM *inverse_3 = BN_mod_inverse(NULL, m_s_2, key_pair_3->modulus, ctx);

    BIGNUM *term_1 = BN_new();
    BN_mul(term_1, ciphertext_1, m_s_0, ctx);
    BN_mul(term_1, term_1, inverse_1, ctx);

    BIGNUM *term_2 = BN_new();
    BN_mul(term_2, ciphertext_2, m_s_1, ctx);
    BN_mul(term_2, term_2, inverse_2, ctx);

    BIGNUM *term_3 = BN_new();
    BN_mul(term_3, ciphertext_3, m_s_2, ctx);
    BN_mul(term_3, term_3, inverse_3, ctx);

    BIGNUM *total = BN_new();
    BN_add(total, term_1, term_2);
    BN_add(total, total, term_3);

    //Multiply together the moduli
    BIGNUM *combined_mod = BN_dup(key_pair_1->modulus);
    BN_mul(combined_mod, combined_mod, key_pair_2->modulus, ctx);
    BN_mul(combined_mod, combined_mod, key_pair_3->modulus, ctx);

    //Reduce the total by the combined moduli
    BN_mod(total, total, combined_mod, ctx);

    //Now to calculate the cube root of total
    BIGNUM *plaintext = nth_root(total, 3);

    if (BN_cmp(plaintext, m) == 0) {
        printf("Set 5 Challenge 40 Successful Recovered message: %s\n", message);
    } else {
        printf("Set 5 Challenge 40 FAILED Unable to recover message\n");
    }

    BN_free(e);
    BN_free(m);
    BN_free(ciphertext_1);
    BN_free(ciphertext_2);
    BN_free(ciphertext_3);

    BN_free(m_s_0);
    BN_free(m_s_1);
    BN_free(m_s_2);

    BN_free(inverse_1);
    BN_free(inverse_2);
    BN_free(inverse_3);

    BN_free(term_1);
    BN_free(term_2);
    BN_free(term_3);

    BN_free(combined_mod);
    BN_free(total);
    BN_free(plaintext);

    free(hex_message);

    BN_CTX_free(ctx);

    rsa_keypair_free(key_pair_1);
    rsa_keypair_free(key_pair_2);
    rsa_keypair_free(key_pair_3);

    return EXIT_SUCCESS;
}
