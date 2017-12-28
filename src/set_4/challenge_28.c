#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../common.h"
#include "../sha1.h"
#include "../test.h"

uint32_t swap(uint32_t num) {
    uint32_t swapped = ((num>>24)&0xff) | // move byte 3 to byte 0
                    ((num<<8)&0xff0000) | // move byte 1 to byte 2
                    ((num>>8)&0xff00) | // move byte 2 to byte 1
                    ((num<<24)&0xff000000); // byte 0 to byte 3
    return swapped;
}

int main(void) {
    //const char *mesg = "abc";

#if 0
    char mesg[64];
    memset(mesg, 'a', 64);

    unsigned char hash[20];

    SHA1((char *) hash, mesg, 64);

    for (size_t i = 0; i < 20; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");


    SHA1_CTX ctx;
    SHA1Init(&ctx);

    uint32_t state[5];

    memcpy(&state[0], hash, sizeof(uint32_t));
    memcpy(&state[1], hash + 4, sizeof(uint32_t));
    memcpy(&state[2], hash + 8, sizeof(uint32_t));
    memcpy(&state[3], hash + 12, sizeof(uint32_t));
    memcpy(&state[4], hash + 16, sizeof(uint32_t));

    state[0] = swap(state[0]);
    state[1] = swap(state[1]);
    state[2] = swap(state[2]);
    state[3] = swap(state[3]);
    state[4] = swap(state[4]);

    printf("My block: %08x\n", state[0]);
    printf("My block: %08x\n", state[1]);
    printf("My block: %08x\n", state[2]);
    printf("My block: %08x\n", state[3]);
    printf("My block: %08x\n", state[4]);

    uint32_t new_state[5];

    memcpy(new_state, state, 5 * 4);

    char new_mesg[128];
    memset(new_mesg, 'a', 128);

    SHA1((char *) hash, new_mesg, 128);

    for (size_t i = 0; i < 20; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");




    ctx.state[0] = state[0];
    ctx.state[1] = state[1];
    ctx.state[2] = state[2];
    ctx.state[3] = state[3];
    ctx.state[4] = state[4];


    SHA1Update(&ctx, mesg, 64);
    SHA1Final((unsigned char *)hash, &ctx);


    for (size_t i = 0; i < 20; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");
#else
    const char *mesg = "abc";
    //const char *mesg = "The quick brown fox jumps over the lazy dog";

    hash((const unsigned char *) mesg, strlen(mesg));
#endif

    return EXIT_SUCCESS;
}
