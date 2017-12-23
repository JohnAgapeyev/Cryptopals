#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../common.h"

int main(void) {
    const char *mesg = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    const char *key = "YELLOW SUBMARINE";
    unsigned char *decoded = base_64_decode((const unsigned char *) mesg, strlen(mesg));

    unsigned char *plaintext = aes_128_ctr_decrypt(decoded, strlen((const char *) decoded), (const unsigned char *) key, 0);

    printf("Set 3 Challenge 18 Decrypted string: ");
    print_n_chars(plaintext, strlen((const char *) decoded));

    free(decoded);
    free(plaintext);

    return EXIT_SUCCESS;
}
