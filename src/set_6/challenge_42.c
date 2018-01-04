#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

BIGNUM *sign_message(const RSA_Keypair *key_pair, const unsigned char *mesg, const size_t len) {
    unsigned char *hash = sha1_hash(mesg, len);

    //1024 bits == 128 bytes
    unsigned char input[129];

    input[0] = 0x00;
    input[1] = 0x01;

    memset(input + 2, 0xff, 100);

    input[102] = 0x00;
    input[103] = 'A';
    input[104] = 'S';
    input[105] = 'N';
    input[106] = '.';
    input[107] = '1';

    memcpy(input + 108, hash, 20);

    input[128] = '\0';

    unsigned char *hex = hex_encode(input, 128);

    BIGNUM *input_bn = hex_to_bignum((const char *) hex);

    BIGNUM *out = rsa_encrypt(input_bn, key_pair->private, key_pair->modulus);

    free(hash);
    free(hex);
    BN_free(input_bn);

    return out;
}

bool verify_signature(const unsigned char *mesg, const size_t len, const RSA_Keypair *key_pair, const BIGNUM *signature) {
    BIGNUM *result = rsa_decrypt(signature, key_pair->public, key_pair->modulus);

    char *result_str = BN_bn2hex(result);

    //This is needed since the BIGNUM removes leading zeroes
    unsigned char modified[strlen(result_str) + 2];
    memcpy(modified + 2, result_str, strlen(result_str));
    modified[0] = '0';
    modified[1] = '0';

    unsigned char *decoded = hex_decode((unsigned char *) modified, strlen(result_str) + 2);

    unsigned char *hash = sha1_hash(mesg, len);

    if (decoded[0] != 0x00) {
        BN_free(result);
        free(result_str);
        free(decoded);
        free(hash);
        return false;
    }
    if (decoded[1] != 0x01) {
        BN_free(result);
        free(result_str);
        free(decoded);
        free(hash);
        return false;
    }
    unsigned char *suffix_start = memchr(decoded + 2, 0x00, strlen((const char *) decoded) - 2);
    if (suffix_start == NULL) {
        BN_free(result);
        free(result_str);
        free(decoded);
        free(hash);
        return false;
    }
    const char *suffix_str = "ASN.1";
    if (strncmp((const char *) suffix_start + 1, suffix_str, strlen(suffix_str)) != 0) {
        BN_free(result);
        free(result_str);
        free(decoded);
        free(hash);
        return false;
    }
    if (memcmp(suffix_start + 1 + strlen(suffix_str), hash, 20) != 0) {
        BN_free(result);
        free(result_str);
        free(decoded);
        free(hash);
        return false;
    }
    BN_free(result);
    free(result_str);
    free(decoded);
    free(hash);
    return true;
}

BIGNUM *forge_signature(const unsigned char *mesg, const size_t len) {
    unsigned char *hash = sha1_hash(mesg, len);

    unsigned char input[128];
    input[0] = 0x00;
    input[1] = 0x01;
    input[2] = 0xff;
    input[3] = 0x00;
    input[4] = 'A';
    input[5] = 'S';
    input[6] = 'N';
    input[7] = '.';
    input[8] = '1';
    memcpy(input + 9, hash, 20);
    memset(input + 29, 0x00, 128 - 29);

    unsigned char *hex = hex_encode(input, 128);

    BIGNUM *input_bn = hex_to_bignum((const char *) hex);

    BIGNUM *root = nth_root(input_bn, 3);
    BN_add(root, root, BN_value_one());

    free(hash);
    free(hex);
    BN_free(input_bn);

    return root;
}

int main(void) {
    const char *e_str = "3";
    const char *message = "hi mom";
    BIGNUM *e = hex_to_bignum(e_str);
    const RSA_Keypair *keys = generate_rsa_keys(e, 1024);
    BIGNUM *signature = sign_message(keys, (const unsigned char *) message, strlen(message));
    if (verify_signature((const unsigned char *) message, strlen(message), keys, signature)) {
        printf("Set 6 Challenge 42 Valid signature validated correctly\n");
    } else {
        printf("Set 6 Challenge 42 FAILED Valid signature failed to validate\n");
    }
    BIGNUM *forged = forge_signature((const unsigned char *) message, strlen(message));
    if (verify_signature((const unsigned char *) message, strlen(message), keys, forged)) {
        printf("Set 6 Challenge 42 Forged signature validated correctly\n");
    } else {
        printf("Set 6 Challenge 42 FAILED Forged signature failed to validate\n");
    }

    BN_free(e);
    BN_free(forged);
    BN_free(signature);

    rsa_keypair_free(keys);

    return EXIT_SUCCESS;
}
