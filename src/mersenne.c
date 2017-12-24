#include "mersenne.h"

static const unsigned int w = 32;
static const unsigned int n = 624;
static const unsigned int m = 397;
static const unsigned int r = 31;

static const unsigned int a = 0x9908b0df;

static const unsigned int u = 11;
static const unsigned int d = 0xffffffff;

static const unsigned int s = 7;
static const unsigned int b = 0x9d2c5680;

static const unsigned int t = 15;
static const unsigned int c = 0xefc60000;

static const unsigned int l = 18;

static const unsigned int f = 1812433253;

static unsigned int temper(unsigned int x);
static void generate_numbers(twister *twist);

void seed_twister(twister *twist, unsigned int seed) {
    twist->state[0] = seed;
    twist->index = n;
    for (unsigned int i = 1; i < n; ++i) {
        twist->state[i] = f * (twist->state[i - 1] ^ (twist->state[i - 1] >> (w - 2))) + i;
    }
}

unsigned int get_random(twister *twist) {
    if (twist->index == n) {
        generate_numbers(twist);
        twist->index = 0;
    }
    return temper(twist->state[(twist->index++ % n)]);
}

unsigned int temper(unsigned int x) {
    unsigned int y = x ^ ((x >> u) & d);
    y = y ^ ((y << s) & b);
    y = y ^ ((y << t) & c);
    return y ^ (y >> l);
}

void generate_numbers(twister *twist) {
    for (unsigned int i = 0; i < n; ++i) {
        unsigned int y = (twist->state[i] & (1ul << r)) + ((twist->state[(i + 1) % n]) & ((1ul << r) - 1));
        twist->state[i] = twist->state[(i + m) % n] ^ (y >> 1);
        if (y & 1) {
            twist->state[i] ^= a;
        }
    }
}
