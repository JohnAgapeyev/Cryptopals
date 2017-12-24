#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <omp.h>
#include "../common.h"
#include "../mersenne.h"

unsigned int seed_and_get(void) {
    unsigned int first_wait = rand() % 10;
    sleep(first_wait);
    twister t;
    unsigned int seed = time(NULL);
    //The code can handle all 32 bit seed values, but this is done to prevent waiting for 10+ minutes for a result
    seed %= USHRT_MAX;
    printf("Using seed %d\n", seed);
    seed_twister(&t, seed);
    unsigned int second_wait = rand() % 10;
    sleep(second_wait);
    return get_random(&t);
}

int main(void) {
    printf("Set 3 Challenge 22\n");
    unsigned int target = seed_and_get();

    twister t;
    bool found_target = false;
    unsigned int seed;
    for (unsigned int i = 0; i < UINT_MAX; ++i) {
        seed_twister(&t, i);
        if (get_random(&t) == target) {
            found_target = true;
            seed = i;
            break;
        }
    }
    if (found_target) {
        printf("Seed used was %d\n", seed);
    } else {
        printf("FAILURE Unable to find seed\n");
    }

    return EXIT_SUCCESS;
}
