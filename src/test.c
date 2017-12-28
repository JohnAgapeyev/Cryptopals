#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <byteswap.h>

#include "common.h"
#include "test.h"

#define SWAP 1

unsigned char *hash(const unsigned char *mesg, const size_t len) {
    size_t padded_len = ((len / 64) + 1) * 64;
    size_t pad_count = padded_len - len;

    unsigned char *input = checked_malloc(padded_len);

    memcpy(input, mesg, len);

    input[len] = 0x80;

    memset(input + len + 1, 0, pad_count);

    uint64_t m_len = len * 8;
    m_len = __bswap_64(m_len);

    memcpy(input + padded_len - sizeof(uint64_t), &m_len, sizeof(uint64_t));

    for (size_t i = 0; i < padded_len; ++i) {
        printf("%02x", input[i]);
    }
    printf("\n");

    printf("%d\n", padded_len);

#if 1
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
#else
    uint32_t h0 = __bswap_32(0x67452301);
    uint32_t h1 = __bswap_32(0xEFCDAB89);
    uint32_t h2 = __bswap_32(0x98BADCFE);
    uint32_t h3 = __bswap_32(0x10325476);
    uint32_t h4 = __bswap_32(0xC3D2E1F0);
#endif

    //printf("%08x\n", 0xa9993e36 - 0x67452301);
    //printf("%08x\n", 0x9cd0d89d - 0xC3D2E1F0);

    for (size_t i = 0; i < padded_len / 64; ++i) {
        uint32_t word_list[80];

        //Split 64 byte chunk into 16 32 bit words
        for (size_t j = 0; j < 16; ++j) {
            memcpy(word_list + j, input + (i * 64) + (j * sizeof(uint32_t)), sizeof(uint32_t));
            word_list[j] = __bswap_32(word_list[j]);
        }

        //Extend those 16 32 bit words into 80 32 bit words
        for (size_t j = 16; j < 80; ++j) {
            //word_list[j] = (word_list[j - 3] ^ word_list[j - 8] ^ word_list[j - 14] ^ word_list[j - 16]) << 1;
            //uint32_t temp = (__bswap_32(word_list[j - 3]) ^ __bswap_32(word_list[j - 8]) ^ __bswap_32(word_list[j - 14]) ^ __bswap_32(word_list[j - 16]));
            uint32_t temp = ((word_list[j - 3]) ^ (word_list[j - 8]) ^ (word_list[j - 14]) ^ (word_list[j - 16]));
            word_list[j] = temp << 1;
            if (j == 16) {
                //printf("%08x\n", word_list[j - 3]);
                //printf("%08x\n", word_list[j - 8]);
                //printf("%08x\n", word_list[j - 14]);
                //printf("%08x\n", word_list[j - 16]);
                //printf("%08x\n", temp);
                //printf("%08x\n", word_list[j]);
                //printf("%08x\n", __bswap_32(word_list[j]));
                //printf("\n");
            }
            //word_list[j] = __bswap_32(word_list[j]);
        }

        for (size_t j = 0; j < 80; ++j) {
            //word_list[j] = __bswap_32(word_list[j]);
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        printf("%08x\n", a);

        for (size_t j = 0; j < 80; ++j) {
            uint32_t f = 0;
            uint32_t k = 0;
            if (j <= 19) {
                f = (b & c) | ((~b) & d);
#if 1
                k = 0x5A827999;
#else
                k = __bswap_32(0x5A827999);
#endif
            } else if (j <= 39) {
                f = b ^ c ^ d;
#if 1
                k = 0x6ED9EBA1;
#else
                k = __bswap_32(0x6ED9EBA1);
#endif
            } else if (j <= 59) {
                f = (b & c) | (b & d) | (c & d);
#if 1
                k = 0x8F1BBCDC;
#else
                k = __bswap_32(0x8F1BBCDC);
#endif
            } else if (j <= 79) {
                f = b ^ c ^ d;
#if 1
                k = 0xCA62C1D6;
#else
                k = __bswap_32(0xCA62C1D6);
#endif
            } else {
                printf("Something went wrong\n");
                abort();
            }

            uint32_t temp = __bswap_32((a << 5) + f + e + k + word_list[j]);
            e = d;
            d = c;
            c = b << 30;
            b = a;
            a = temp;
        }

        //h0 += a;
        h0 += 0x42541b35;

        printf("%08x\n", a);
        printf("%08x\n", 0x42541b35);


        h1 += b;
        h2 += c;
        h3 += d;
        //h4 += e;
        h4 += 0xd8fdf6ad;

        //printf("%08x\n", e);
        //printf("%08x\n", 0xd8fdf6ad);
    }

    //h0 = 0xa9993e36;

#if 1
    printf("%08x ", h0);
    printf("%08x ", h1);
    printf("%08x ", h2);
    printf("%08x ", h3);
    printf("%08x ", h4);
    printf("\n");
#else
    printf("%08x ", __bswap_32(h0));
    printf("%08x ", __bswap_32(h1));
    printf("%08x ", __bswap_32(h2));
    printf("%08x ", __bswap_32(h3));
    printf("%08x ", __bswap_32(h4));
    printf("\n");
#endif

    return NULL;
}
