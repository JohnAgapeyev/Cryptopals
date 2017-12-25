#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include "../common.h"
#include "../mersenne.h"

unsigned char *twister_encrypt(const unsigned char *mesg, const size_t len, const unsigned short seed) {
    twister t;
    seed_twister(&t, seed);

    unsigned char *out = checked_malloc(len);

    for (size_t i = 0; i < len; ++i) {
        out[i] = get_random(&t) ^ mesg[i];
    }
    return out;
}

unsigned char *twister_decrypt(const unsigned char *mesg, const size_t len, const unsigned short seed) {
    return twister_encrypt(mesg, len, seed);
}

unsigned char *oracle(const unsigned char *mesg, const size_t len, const unsigned short seed, size_t *cipher_len) {
    size_t rand_len = rand() % 100;
    unsigned char input[len + rand_len];
    for (size_t i = 0; i < rand_len; ++i) {
        input[i] = rand();
    }
    memcpy(input + rand_len, mesg, len);

    if (cipher_len) {
        *cipher_len = len + rand_len;
    }

    return twister_encrypt(input, len + rand_len, seed);
}

/*
 * Don't really think I need to determine the password token since that's literally just the below code
 * If it is a token, the seed would be calculated in the below loops
 * If it's not a token, the seed would not be found
 */
int main(void) {
    srand(time(NULL));
    const char *mesg = "aaaaaaaaaaaaaa";
    const unsigned short seed = rand() % USHRT_MAX;

    size_t cipher_len;
    unsigned char *ciphertext = oracle((const unsigned char *) mesg, strlen(mesg), seed, &cipher_len);

    size_t rand_len = cipher_len - strlen(mesg);

    twister t;
    unsigned long calculated_seed = -1;
    for (unsigned short i = 0; i < USHRT_MAX; ++i) {
        seed_twister(&t, i);
        for (size_t j = 0; j < cipher_len; ++j) {
            unsigned int num = get_random(&t);
            if (j < rand_len) {
                //Ignore the random bytes
                continue;
            }
            if ((unsigned char) (num ^ ciphertext[j]) != 'a') {
                //This is not our seed
                break;
            }
            if (j == cipher_len - 1) {
                //Last iteration
                if ((unsigned char) (num ^ ciphertext[j]) == 'a') {
                    //This is our seed
                    calculated_seed = i;
                    goto end;
                }
            }
        }
    }
end:
    if (calculated_seed > USHRT_MAX) {
        printf("Unable to locate seed!\n");
    } else {
        printf("Seed calculated was: %lu\n", calculated_seed);
        printf("Seed used was: %d\n", seed);
    }

    free(ciphertext);

    return EXIT_SUCCESS;
}
