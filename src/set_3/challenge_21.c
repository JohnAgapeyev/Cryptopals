#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../common.h"
#include "../mersenne.h"

int main(void) {
    twister t;
    seed_twister(&t, 1234);

    printf("Set 3 Challenge 21 Twister seeded with value 1234 First 10 outputs: ");
    for (int i = 0; i < 10; ++i) {
        printf("%08x ", get_random(&t));
    }
    printf("\n");

    return EXIT_SUCCESS;
}
