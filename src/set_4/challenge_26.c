#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h>
#include "../common.h"

unsigned char *key = NULL;
unsigned short nonce = 0;
const char *prefix = "comment1=cooking%20MCs;userdata=";
const char *suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

unsigned char *encrypt_oracle(const unsigned char *mesg, const size_t len, size_t *out_len) {
    if (key == NULL) {
        key = generate_random_aes_key();
        nonce = rand() % USHRT_MAX;
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

    if (out_len) {
        *out_len = strlen(prefix) + index + strlen(suffix);
    }

    unsigned char *rtn = aes_128_ctr_encrypt(plaintext, strlen(prefix) + index + strlen(suffix), key, nonce);
    return rtn;
}

bool validate_cookie(const unsigned char *mesg, const size_t len) {
    //We can assume the attacker has the iv
    unsigned char *plaintext = aes_128_ctr_decrypt(mesg, len, key, nonce);
    unsigned char null_terminated[len + 1];
    memcpy(null_terminated, plaintext, len);
    null_terminated[len] = '\0';

    print_n_chars(null_terminated, len);

    free(plaintext);

    return strstr((const char *) null_terminated, ";admin=true;") != NULL;
}

int main(void) {
    srand(time(NULL));
    unsigned char input[160];
    memset(input, 0, 160);
    size_t cipher_len;
    unsigned char *ciphertext = encrypt_oracle(input, 160, &cipher_len);

    ciphertext[32] ^= ';';
    ciphertext[33] ^= 'a';
    ciphertext[34] ^= 'd';
    ciphertext[35] ^= 'm';
    ciphertext[36] ^= 'i';
    ciphertext[37] ^= 'n';
    ciphertext[38] ^= '=';
    ciphertext[39] ^= 't';
    ciphertext[40] ^= 'r';
    ciphertext[41] ^= 'u';
    ciphertext[42] ^= 'e';
    ciphertext[43] ^= ';';

    if (validate_cookie(ciphertext, cipher_len)) {
        printf("Set 4 Challenge 26 Passed!\n");
    } else {
        printf("Set 4 Challenge 26 FAILED Unable to validate cookie as admin!\n");
    }

    free(key);
    return EXIT_SUCCESS;
}
