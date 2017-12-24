#ifndef MT_H
#define MT_H

typedef struct {
    unsigned int state[624];
    unsigned int index;
} twister;

void seed_twister(twister *twist, unsigned int seed);
unsigned int get_random(twister *twist);

#endif
