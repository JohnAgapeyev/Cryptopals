#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h>
#include "../common.h"

unsigned char *key = NULL;
unsigned char *iv = NULL;
const char *prefix = "comment1=cooking%20MCs;userdata=";
const char *suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

unsigned char *encrypt_oracle(const unsigned char *mesg, const size_t len, size_t *out_len) {
    if (key == NULL) {
        key = generate_random_aes_key();
    }
    if (iv == NULL) {
        //Key and iv are the same length
        iv = generate_random_aes_key();
    }
    unsigned char plaintext[strlen(prefix) + len + strlen(suffix)];
    memcpy(plaintext, prefix, strlen(prefix));

    size_t index = 0;
    for (size_t i = 0; i < len; ++i) {
        if (mesg[i] != ';' && mesg[i] != '=') {
            plaintext[strlen(prefix) + index] = mesg[i];
            ++index;
        }
    }
    memcpy(plaintext + strlen(prefix) + index, suffix, strlen(suffix));

    unsigned char *padded = pkcs7_pad(plaintext, strlen(prefix) + index + strlen(suffix), 16);
    unsigned long padded_len = get_padded_length(strlen(prefix) + index + strlen(suffix), 16);
    unsigned char *rtn = aes_128_cbc_encrypt(padded, padded_len, key, iv, out_len);
    free(padded);
    return rtn;
}

bool validate_cookie(const unsigned char *mesg, const size_t len) {
    //We can assume the attacker has the iv
    size_t plain_len;
    unsigned char *plaintext = aes_128_cbc_decrypt(mesg, len, key, iv, &plain_len);
    unsigned char null_terminated[plain_len + 1];
    memcpy(null_terminated, plaintext, plain_len);
    null_terminated[plain_len] = '\0';

    print_n_chars(null_terminated, plain_len);

    free(plaintext);

    return strstr((const char *) null_terminated, ";admin=true;") != NULL;
}

int main(void) {
    srand(time(NULL));
    unsigned char input[160];
    memset(input, 0, 160);
    size_t cipher_len;
    unsigned char *ciphertext = encrypt_oracle(input, 160, &cipher_len);

    ciphertext[16] ^= ';';
    ciphertext[17] ^= 'a';
    ciphertext[18] ^= 'd';
    ciphertext[19] ^= 'm';
    ciphertext[20] ^= 'i';
    ciphertext[21] ^= 'n';
    ciphertext[22] ^= '=';
    ciphertext[23] ^= 't';
    ciphertext[24] ^= 'r';
    ciphertext[25] ^= 'u';
    ciphertext[26] ^= 'e';
    ciphertext[27] ^= ';';

    if (validate_cookie(ciphertext, cipher_len)) {
        printf("Set 2 Challenge 16 Passed!\n");
    } else {
        printf("Set 2 Challenge 16 FAILED Unable to validate cookie as admin!\n");
    }

    free(key);
    return EXIT_SUCCESS;
}
