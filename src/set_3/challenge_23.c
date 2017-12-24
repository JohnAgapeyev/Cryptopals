#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include "../common.h"
#include "../mersenne.h"

/**
 * This method was directly copied from https://cypher.codes/writing/cryptopals-challenge-set-3
 */
unsigned int undo_right_shift(unsigned int value, unsigned int shift) {
    unsigned int result = 0;
    for (unsigned int i = 0; i < 32 / shift + 1; ++i) {
        result ^= value >> (shift * i);
    }
    return result;
}

/**
 * This method was directly copied from https://cypher.codes/writing/cryptopals-challenge-set-3
 */
unsigned int undo_left_shift_and(unsigned int value, unsigned int shift, unsigned int mask) {
    unsigned int result = 0;
    for (unsigned int i = 0; i < 32 / shift + 1; ++i) {
        unsigned int part_mask = (0xffffffff >> (32 - shift)) << (shift * i);
        unsigned int part = value & part_mask;
        value ^= (part << shift) & mask;
        result |= part;
    }
    return result;
}

unsigned int untemper(unsigned int z) {
    unsigned int y = z;
    y = undo_right_shift(y, 18);
    y = undo_left_shift_and(y, 15, 0xefc60000);
    y = undo_left_shift_and(y, 7, 0x9d2c5680);
    y = undo_right_shift(y, 11);
    return y;
}

int main(void) {
    twister example;
    seed_twister(&example, 1234);

    unsigned int example_state[624];

    for (int i = 0; i < 624; ++i) {
        example_state[i] = untemper(get_random(&example));
    }

    twister copy;
    copy.index = 624;
    memcpy(&copy.state, example_state, sizeof(unsigned int) * 624);

    for (int i = 0; i < 624; ++i) {
        if (get_random(&copy) != get_random(&example)) {
            printf("My numbers didn't match up!\n");
            return EXIT_FAILURE;
        }
    }
    printf("Set 3 Challenge 23 Mersenne Twister state successfully copied\n");

    return EXIT_SUCCESS;
}
