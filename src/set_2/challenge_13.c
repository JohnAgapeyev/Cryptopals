#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../common.h"

unsigned char *key = NULL;

void parse_kv_string(const char *mesg, const size_t len) {
    char buffer[len];
    memcpy(buffer, mesg, len);

    char *key = strtok(buffer, "=&");
    char *value = strtok(NULL, "=&");

    printf("%s: %s\n", key, value);

    while ((key = strtok(NULL, "=&")) != NULL) {
        value = strtok(NULL, "=&");
        if (value == NULL) {
            break;
        }
        printf("%s: %s\n", key, value);
    }
}

char *profile_for(const char *email, const size_t len) {
    const char *prefix = "email=";
    const char *suffix = "&uid=10&role=user";

    char *out = checked_malloc(len + strlen(prefix) + strlen(suffix) + 1);

    memcpy(out, prefix, strlen(prefix));

    size_t index = 0;
    for (size_t i = 0; i < len; ++i) {
        if (email[i] != '=' && email[i] != '&') {
            out[index + strlen(prefix)] = email[i];
            ++index;
        }
    }
    memcpy(out + strlen(prefix) + index, suffix, strlen(suffix));
    out[strlen(prefix) + index + strlen(suffix)] = '\0';
    return out;
}

unsigned char *encrypt_oracle(const unsigned char *mesg, const size_t len, size_t *cipher_len) {
    if (key == NULL) {
        key = generate_random_aes_key();
    }

    unsigned char *padded = pkcs7_pad(mesg, len, 16);
    unsigned char *ciphertext = aes_128_ecb_encrypt(padded, (((len) / 16) + 1) * 16, key, cipher_len);

    free(padded);
    return ciphertext;
}

void parse_encrypted(const unsigned char *mesg, const size_t len) {
    size_t plain_len;
    unsigned char *plaintext = aes_128_ecb_decrypt(mesg, len, key, &plain_len);

    unsigned char null_terminated_plaintext[plain_len + 1];
    memcpy(null_terminated_plaintext, plaintext, plain_len);
    null_terminated_plaintext[plain_len] = '\0';

    parse_kv_string((const char *) null_terminated_plaintext, plain_len + 1);

    free(plaintext);
}

int main(void) {
    const char *injected_email = "aaaaaaaaaaadmin";
    char padding[12];
    memset(padding, 11, 11);
    padding[11] = '\0';

    char injected[strlen(injected_email) + 12];

    memcpy(injected, injected_email, strlen(injected_email));
    memcpy(injected + strlen(injected_email), padding, 12);

    const char *blank = "aaaaaaaaaaaaa";

    unsigned char *injected_profile = (unsigned char *) profile_for(injected, strlen(injected));
    size_t modified_len;
    unsigned char *modified = encrypt_oracle(injected_profile, strlen((const char *) injected_profile), &modified_len);

    unsigned char *clean_profile = (unsigned char *) profile_for(blank, strlen(blank));
    size_t clean_len;
    unsigned char *clean = encrypt_oracle(clean_profile, strlen((const char *) clean_profile), &clean_len);

    printf("Set 2 Challenge 13: \n");
    printf("Base cookie: \n");

    parse_encrypted(clean, clean_len);

    printf("Injected cookie: \n");
    memcpy(clean + 32, modified + 16, 16);

    parse_encrypted(clean, clean_len);

    printf("\n");

    return EXIT_SUCCESS;
}
