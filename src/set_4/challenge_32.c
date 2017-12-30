#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h>
#include "../common.h"

#define MICRO_IN_SEC 1000ul * 1000ul
#define NANO_IN_SEC 1000ul * MICRO_IN_SEC

//The code works with larger sleeps, it just takes longer to actually finish
#define SLEEP_MILLIS 1 * MICRO_IN_SEC

unsigned char *hmac_sha1(const unsigned char *key, const size_t key_len, const unsigned char *mesg, const size_t mesg_len) {
    unsigned char padded_key[20];
    if (key_len <= 20) {
        memset(padded_key, 0, 20);
        memcpy(padded_key, key, key_len);
    } else {
        unsigned char *hashed_key = sha1_hash(key, key_len);
        memcpy(padded_key, hashed_key, 20);
        free(hashed_key);
    }

    unsigned char outer[20];
    unsigned char inner[20];
    memset(outer, 0x5c, 20);
    memset(inner, 0x36, 20);

    unsigned char *inner_xor = xor_buffer(inner, padded_key, 20);
    unsigned char *outer_xor = xor_buffer(outer, padded_key, 20);

    unsigned char inner_input[20 + mesg_len];
    memcpy(inner_input, inner_xor, 20);
    memcpy(inner_input + 20, mesg, mesg_len);

    unsigned char *inner_hash = sha1_hash(inner_input, 20 + mesg_len);

    unsigned char final_input[40];
    memcpy(final_input, outer_xor, 20);
    memcpy(final_input + 20, inner_hash, 20);

    unsigned char *rtn = sha1_hash(final_input, 40);

    free(inner_xor);
    free(outer_xor);
    free(inner_hash);

    return rtn;
}

void sleep(const unsigned long long ns) {
    struct timespec current;
    current.tv_sec = 0;
    current.tv_nsec = ns;
    nanosleep(&current, NULL);
}

bool insecure_compare(const unsigned char *first, const unsigned char *second, const size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (first[i] != second[i]) {
            return false;
        }
        sleep(SLEEP_MILLIS);
    }
    return true;
}

unsigned long long get_time(void) {
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    return 1000000 * tv.tv_sec + (tv.tv_nsec / 1000);
}

int main(void) {
    const char *mesg = "Hello World!";
    const char *key = "YELLOW SUBMARINE";
    unsigned char *mac = hmac_sha1((const unsigned char *) key, strlen(key), (const unsigned char *) mesg, strlen(mesg));

    printf("Original MAC: ");
    for (size_t i = 0; i < 20; ++i) {
        printf("%02x", mac[i]);
    }
    printf("\n");

    unsigned char modified[20];
    memset(modified, 0, 20);

    printf("Blind    MAC: ");
    for (size_t i = 0; i < 20; ++i) {
        unsigned long long maximum = 0;
        unsigned char best = 0x00;
        for (unsigned char j = 0; j < UCHAR_MAX; ++j) {
            modified[i] = j;

            unsigned long long old = get_time();
            insecure_compare(mac, modified, 20);
            unsigned long long new = get_time();

            if (new - old > maximum) {
                maximum = new - old;
                best = j;
            }
        }
        modified[i] = best;
        printf("%02x", best);
        fflush(stdout);
    }
    printf("\n");

    if (insecure_compare(mac, modified, 20)) {
        printf("Set 4 Challenge 32 Passed Calculated and reference MAC are identical\n");
    } else {
        printf("Set 4 Challenge 32 FAILED MAC was not created successfully\n");
    }

    free(mac);

    return EXIT_SUCCESS;
}
