#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "../common.h"

bool oracle(BIGNUM *ciphertext, const RSA_Keypair *keys) {
    BIGNUM *plaintext = rsa_decrypt(ciphertext, keys->private, keys->modulus);

    unsigned char data[BN_num_bytes(plaintext)];
    BN_bn2binpad(plaintext, data, BN_num_bytes(plaintext) + 1);

    bool rtn = false;

    if (data[0] != 0x00) {
        goto done;
    }
    if (data[1] != 0x02) {
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
    unsigned char *hex_message = hex_encode(mesg, (strlen(mesg) / 4) * 3);
    BIGNUM *m = hex_to_bignum((const char *) hex_message);

    //Fill buffer with random padding bytes
    unsigned char random_data[BN_num_bytes(key_pair->modulus) - 3 - BN_num_bytes(m)];
    RAND_bytes(random_data, BN_num_bytes(key_pair->modulus) - 3 - BN_num_bytes(m));

    unsigned char padded_data[3 + sizeof(random_data) + BN_num_bytes(m)];
    //Write the padded data to the buffer
    padded_data[0] = 0x00;
    padded_data[1] = 0x02;
    memcpy(padded_data + 2, random_data, sizeof(random_data));
    padded_data[sizeof(random_data) + 2] = 0x00;
    BN_bn2bin(m, padded_data + 2 + sizeof(random_data));

    BIGNUM *plaintext = BN_bin2bn(padded_data, sizeof(padded_data), NULL);

    BIGNUM *ciphertext = rsa_encrypt(plaintext, key_pair->public, key_pair->modulus);

    free(hex_message);
    BN_free(m);
    BN_free(plaintext);

    return ciphertext;
}

int main(void) {
    const char *e_str = "65537";
    BIGNUM *e = hex_to_bignum(e_str);
    const RSA_Keypair *key_pair = generate_rsa_keys(e, 256);

    const char *message = "kick it, CC";
    BIGNUM *padded = pkcs1v15_pad(message, strlen(message), key_pair);

    if (!oracle(padded, key_pair)) {
        printf("Padded test did not work\n");
        goto cleanup;
    }

cleanup:
    BN_free(e);
    rsa_keypair_free(key_pair);
    BN_free(padded);

    return EXIT_SUCCESS;
}
