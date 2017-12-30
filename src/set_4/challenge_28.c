#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../common.h"

unsigned char *keyed_mac(const unsigned char *key, const size_t key_len, const unsigned char *mesg, const size_t mesg_len) {
    unsigned char input[key_len + mesg_len];

    memcpy(input, key, key_len);
    memcpy(input + key_len, mesg, mesg_len);

    return sha1_hash(input, key_len + mesg_len);
}

int main(void) {
    const char *mesg = "This is a test";
    const char *key = "YELLOW SUBMARINE";
    unsigned char *mac = keyed_mac((const unsigned char *) key, strlen(key), (const unsigned char *) mesg, strlen(mesg));

    printf("Set 4 Challenge 28\nMessage: %s\nKey: %s\nMAC: ", mesg, key);
    for (size_t i = 0; i < 20; ++i) {
        printf("%02x", mac[i]);
    }
    printf("\n");
    return EXIT_SUCCESS;
}
