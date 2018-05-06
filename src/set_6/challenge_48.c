/**
 * Fundamentally identical to challenge 47, I just increased the key size to realistic levels
 * for this challenge (2048 bits)
 */
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "../common.h"

struct range {
    BIGNUM *a;
    BIGNUM *b;
};

BIGNUM *B_2;
BIGNUM *B_3;

struct range **range_list;
size_t range_count = 0;
size_t range_allocated = 0;

/*
 * Apparently this "less accurate" version doesn't cause issues in the code
 * I originally had a check that it met the required length, and contained a zero byte
 * in the correct range, but that caused issues
 * So instead I found someone else's example that just did a 2B and 3B range compare instead
 * Oh well, the bleichenbacher paper had very clear rules that I followed, I feel vindicated,
 * even if it didn't work
 */
bool oracle(BIGNUM *ciphertext, const RSA_Keypair *keys) {
    BIGNUM *plaintext = rsa_decrypt(ciphertext, keys->private, keys->modulus);
    bool rtn = (BN_cmp(plaintext, B_2) != -1 && BN_cmp(plaintext, B_3) == -1);
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

void generate_constants(const BIGNUM *n) {
    BIGNUM *B = BN_new();
    BN_set_word(B, 2);

    //B = 2^8(k-2) where k is modulus num bytes
    BN_lshift(B, B, 8 * (BN_num_bytes(n) - 2) - 1);

    B_2 = BN_dup(B);
    B_3 = BN_dup(B);

    BN_mul_word(B_2, 2);
    BN_mul_word(B_3, 3);

    BN_free(B);

    range_list = checked_calloc(100, sizeof(struct range *));
    range_allocated = 100;
}

void free_constants(void) {
    BN_free(B_2);
    BN_free(B_3);

    for (unsigned int i = 0; i < range_allocated; ++i) {
        if (range_list[i]) {
            BN_free(range_list[i]->a);
            BN_free(range_list[i]->b);
            free(range_list[i]);
        }
    }
    free(range_list);
}

void get_range_from_s(const BIGNUM *s, const BIGNUM *n) {
    BIGNUM *calculated_r = BN_new();
    BIGNUM *tmp = BN_new();
    BIGNUM *max_r = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    struct range **new_range_list = checked_calloc(1000, sizeof(struct range *));
    size_t new_range_count = 0;
    size_t new_range_allocated = 1000;

    for (unsigned int i = 0; i < range_count; ++i) {
        struct range *elem = range_list[i];

        //calculated r = ((elem->a * s) - 3B + 1) / n
        BN_mul(calculated_r, elem->a, s, ctx);
        BN_sub(calculated_r, calculated_r, B_3);
        BN_add_word(calculated_r, 1);
        BN_div(calculated_r, NULL, calculated_r, n, ctx);

        //max_r = ((elem->b * s) - B2) / n
        BN_mul(max_r, elem->b, s, ctx);
        BN_sub(max_r, max_r, B_2);
        BN_div(max_r, NULL, max_r, n, ctx);

        for (; BN_cmp(calculated_r, max_r) != 1; BN_add_word(calculated_r, 1)) {
            if (new_range_count == new_range_allocated) {
                new_range_list = checked_realloc(new_range_list, (new_range_allocated + 100) * sizeof(struct range *));
                new_range_allocated += 100;
            }
            struct range *m = checked_malloc(sizeof(struct range));
            new_range_list[new_range_count++] = m;

            m->a = BN_new();
            m->b = BN_new();

            //tmp = (2B + rn) / s
            BN_mul(tmp, calculated_r, n, ctx);
            BN_add(tmp, tmp, B_2);
            BN_div(tmp, NULL, tmp, s, ctx);
            BN_add_word(tmp, 1);

            //m->a = max(elem->a, (2B + rn) / s)
            if (BN_cmp(elem->a, tmp) == 1) {
                BN_copy(m->a, elem->a);
            } else {
                BN_copy(m->a, tmp);
            }

            //tmp = (3B - 1 + rn) / s
            BN_mul(tmp, calculated_r, n, ctx);
            BN_add(tmp, tmp, B_3);
            BN_sub_word(tmp, 1);
            BN_div(tmp, NULL, tmp, s, ctx);

            //m->b = min(elem->b, (3B - 1 + rn) / s)
            if (BN_cmp(elem->b, tmp) == -1) {
                BN_copy(m->b, elem->b);
            } else {
                BN_copy(m->b, tmp);
            }

            //Range is invalid; remove it
            if (BN_cmp(m->a, B_3) == 1 || BN_cmp(m->b, B_2) == -1 || BN_cmp(m->a, m->b) == 1) {
                BN_free(m->a);
                BN_free(m->b);
                free(m);
                --new_range_count;
                new_range_list[new_range_count] = NULL;
            }
        }
    }

    //Free old range list
    for (unsigned int i = 0; i < range_allocated; ++i) {
        if (range_list[i]) {
            BN_free(range_list[i]->a);
            BN_free(range_list[i]->b);
            free(range_list[i]);
        }
    }
    free(range_list);

    //Assign new ranges
    range_list = new_range_list;
    range_count = new_range_count;
    range_allocated = new_range_allocated;

    BN_free(calculated_r);
    BN_free(max_r);
    BN_free(tmp);
    BN_CTX_free(ctx);
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

BIGNUM *generate_next_s(BIGNUM *ciphertext, const RSA_Keypair *keys, const BIGNUM *old_s) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *test = BN_new();

    BN_copy(test, old_s);
    BN_add_word(test, 1);

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

//INITIAL R CALCULATION HAS BEEN VERIFIED USING KNOWN GOOD SOURCE CODE
BIGNUM *generate_new_s(BIGNUM *ciphertext, const RSA_Keypair *keys, const struct range *range, const BIGNUM *s) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *new_s = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *max = BN_new();

    //r = 2 * (((b * s) - 2B) / n)
    BN_mul(r, range->b, s, ctx);
    BN_sub(r, r, B_2);
    BN_div(r, NULL, r, keys->modulus, ctx);
    BN_mul_word(r, 2);
    BN_add_word(r, 1);

    for (;;BN_add_word(r, 1)) {
        //new_s = (2B + (r * n)) / b
        BN_mul(new_s, r, keys->modulus, ctx);
        BN_add(new_s, new_s, B_2);
        BN_div(new_s, NULL, new_s, range->b, ctx);

        //max = (3B + (r * n)) / a
        BN_mul(max, r, keys->modulus, ctx);
        BN_add(max, max, B_3);
        BN_div(max, NULL, max, range->a, ctx);

        if (BN_cmp(new_s, max) == 1) {
            fprintf(stderr, "New S range mismatch\n");
            fprintf(stderr, "%s\n%s\n", BN_bn2hex(new_s), BN_bn2hex(max));
            abort();
        }

        for (; BN_cmp(new_s, max) != 1; BN_add_word(new_s, 1)) {
            BIGNUM *output = rsa_encrypt(new_s, keys->public, keys->modulus);
            BN_mod_mul(output, output, ciphertext, keys->modulus, ctx);

            if (oracle(output, keys)) {
                BN_free(output);
                //Value is padded correctly
                goto done;
            }
            BN_free(output);
        }
    }

done:
    BN_CTX_free(ctx);
    BN_free(r);
    BN_free(max);
    return new_s;
}

int main(void) {
    const char *e_str = "65537";
    BIGNUM *e = hex_to_bignum(e_str);
    const RSA_Keypair *key_pair = generate_rsa_keys(e, 2048);

    generate_constants(key_pair->modulus);

    const char *message = "kick it, CC";
    BIGNUM *padded = pkcs1v15_pad(message, strlen(message), key_pair);

    if (!oracle(padded, key_pair)) {
        fprintf(stderr, "Padded test did not work\n");
        goto cleanup;
    }

    //Get initial S
    //Compute first new range using default range
    //while true:
    //Check new range
    //Calculate new s based on the new range
    //Generate new s based on range len
    //Create new range based on s

    //Calculate initial S value
    BIGNUM *s = generate_initial_s(padded, key_pair);

    //Create initial range
    struct range *start = checked_malloc(sizeof(struct range));
    start->a = BN_dup(B_2);
    start->b = BN_dup(B_3);
    BN_sub_word(start->b, 1);
    range_list[0] = start;
    range_count = 1;

    get_range_from_s(s, key_pair->modulus);

    for (;;) {
        //Range is a single number
        if (range_count == 1 && BN_cmp(range_list[0]->a, range_list[0]->b) == 0) {
            break;
        }
        BIGNUM *tmp_num;
        if (range_count == 1) {
            tmp_num = generate_new_s(padded, key_pair, range_list[0], s);
            BN_free(s);
            s = tmp_num;
        } else if (range_count > 1) {
            tmp_num = generate_next_s(padded, key_pair, s);
            BN_free(s);
            s = tmp_num;
        } else {
            fprintf(stderr, "Range count is zero or negative\n");
            abort();
        }
        get_range_from_s(s, key_pair->modulus);
    }
    BN_free(s);

    BIGNUM *plaintext = rsa_decrypt(padded, key_pair->private, key_pair->modulus);
    if (BN_cmp(plaintext, range_list[0]->a) == 0) {
        printf("Set 6 Challenge 47 PASSED Decryption successful\n");
    } else {
        printf("Set 6 Challenge 47 FAILED Decryption unable to retrieve original plaintext\n");
    }
    BN_free(plaintext);

cleanup:
    rsa_keypair_free(key_pair);
    BN_free(padded);
    free_constants();
    BN_free(e);

    return EXIT_SUCCESS;
}
