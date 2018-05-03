#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "../common.h"

BIGNUM *B_2;
BIGNUM *B_3;
BIGNUM *e;

struct range {
    BIGNUM *a;
    BIGNUM *b;
};

bool oracle(BIGNUM *ciphertext, const RSA_Keypair *keys) {
    BIGNUM *plaintext = rsa_decrypt(ciphertext, keys->private, keys->modulus);

    unsigned char data[BN_num_bytes(plaintext) + 1];
    BN_bn2binpad(plaintext, data, BN_num_bytes(plaintext) + 1);

    bool rtn = false;

    if (data[0] != 0x00) {
        goto done;
    }

    if (data[1] != 0x02) {
        goto done;
    }

    //Length constraint
    if (BN_num_bytes(plaintext) + 1 < BN_num_bytes(keys->modulus)) {
        goto done;
    }

    //Check for a zero termination to the padding
    for (int i = 2; i < BN_num_bytes(plaintext) + 1; ++i) {
        if (data[i] == 0x00) {
            rtn = true;
            goto done;
        }
    }
    rtn = false;

done:
    BN_free(plaintext);
    return rtn;
}

BIGNUM *pkcs1v15_pad(const char *mesg, const size_t len, const RSA_Keypair *key_pair) {
    unsigned char *hex_message = hex_encode((const unsigned char *) mesg, (len / 4) * 3);
    BIGNUM *m = hex_to_bignum((const char *) hex_message);

    size_t random_size = BN_num_bytes(key_pair->modulus) - 3 - BN_num_bytes(m);

    //Fill buffer with random padding bytes
    unsigned char random_data[random_size];
    RAND_bytes(random_data, random_size);

    unsigned char padded_data[3 + random_size + BN_num_bytes(m)];
    //Write the padded data to the buffer
    padded_data[0] = 0x00;
    padded_data[1] = 0x02;
    memcpy(padded_data + 2, random_data, random_size);
    padded_data[random_size + 2] = 0x00;
    BN_bn2bin(m, padded_data + 2 + random_size);

    BIGNUM *plaintext = BN_bin2bn(padded_data, BN_num_bytes(key_pair->modulus), NULL);

    BIGNUM *ciphertext = rsa_encrypt(plaintext, key_pair->public, key_pair->modulus);

    free(hex_message);
    BN_free(m);
    BN_free(plaintext);

    return ciphertext;
}

void generate_constants(void) {
    const char *e_str = "65537";
    e = hex_to_bignum(e_str);

    BIGNUM *B = BN_new();
    BN_set_word(B, 1);

    //B = 2^8(k-2) where k is modulus num bytes
    BN_lshift(B, B, 8 * (32 - 2));

    B_2 = BN_dup(B);
    B_3 = BN_dup(B);

    BN_mul_word(B_2, 2);
    BN_mul_word(B_3, 3);

    BN_free(B);
}

void free_constants(void) {
    BN_free(e);
    BN_free(B_2);
    BN_free(B_3);
}

struct range *get_range_from_s(const BIGNUM *s, const BIGNUM *n, const struct range *prev) {
    struct range *m = checked_malloc(sizeof(struct range));
    m->a = BN_new();
    m->b = BN_new();

    BIGNUM *calculated_r = BN_new();
    BIGNUM *tmp = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    //calculated r = ((prev->a * s) - 3B + 1) / n
    BN_mul(calculated_r, prev->a, s, ctx);
    BN_sub(calculated_r, calculated_r, B_3);
    BN_add_word(calculated_r, 1);
    BN_div(calculated_r, NULL, calculated_r, n, ctx);

    //tmp = ((prev->b * s) - B2) / n
    BN_mul(tmp, prev->b, s, ctx);
    BN_sub(tmp, tmp, B_2);
    BN_div(tmp, NULL, tmp, n, ctx);

    //Average the results to get middle result for r
    BN_add(calculated_r, calculated_r, tmp);
    BN_div_word(calculated_r, 2);

    //tmp = (2B + rn) / s
    BN_mul(tmp, calculated_r, n, ctx);
    BN_add(tmp, tmp, B_2);
    BN_div(tmp, NULL, tmp, s, ctx);

    //m->a = max(prev->a, (2B + rn) / s)
    if (BN_cmp(prev->a, tmp) == 1) {
        BN_copy(m->a, prev->a);
    } else {
        BN_copy(m->a, tmp);
    }

    //tmp = (3B -1 + rn) / s
    BN_mul(tmp, calculated_r, n, ctx);
    BN_add(tmp, tmp, B_3);
    BN_sub_word(tmp, 1);
    BN_div(tmp, NULL, tmp, s, ctx);

    //m->b = min(prev->b, (3B - 1 + rn) / s)
    if (BN_cmp(prev->a, tmp) == -1) {
        BN_copy(m->b, prev->b);
    } else {
        BN_copy(m->b, tmp);
    }

    BN_free(calculated_r);
    BN_free(tmp);
    BN_CTX_free(ctx);

    return m;
}

BIGNUM *generate_initial_s(BIGNUM *ciphertext, const RSA_Keypair *keys) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *test = BN_new();

    BN_div(test, NULL, keys->modulus, B_3, ctx);

    for (;;) {
        BIGNUM *output = rsa_encrypt(test, keys->public, keys->modulus);
        BN_mod_mul(output, output, ciphertext, keys->modulus, ctx);

        if (oracle(output, keys)) {
            BN_free(output);
            //Value is padded correctly
            break;
        }
        BN_free(output);
        BN_add_word(test, 1);
    }
    BN_CTX_free(ctx);
    return test;
}

int main(void) {
    generate_constants();

    const RSA_Keypair *key_pair = generate_rsa_keys(e, 256);

    const char *message = "kick it, CC";
    BIGNUM *padded = pkcs1v15_pad(message, strlen(message), key_pair);

    if (!oracle(padded, key_pair)) {
        fprintf(stderr, "Padded test did not work\n");
        goto cleanup;
    }

    BIGNUM *s1 = generate_initial_s(padded, key_pair);
    printf("Initial s value: %s\n", BN_bn2hex(s1));

    struct range start;
    start.a = B_2;
    start.b = B_3;

    struct range *ran = get_range_from_s(s1, key_pair->modulus, &start);
    printf("Initial range: %s\t%s\n", BN_bn2hex(ran->a), BN_bn2hex(ran->b));

cleanup:
    rsa_keypair_free(key_pair);
    BN_free(padded);
    free_constants();

    return EXIT_SUCCESS;
}
