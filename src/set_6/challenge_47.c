#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "../common.h"

struct range {
    BIGNUM *a;
    BIGNUM *b;
};

BIGNUM *B_2;
BIGNUM *B_3;

struct range **range_list;
size_t range_count = 0;
size_t range_allocated = 0;

bool oracle(BIGNUM *ciphertext, const RSA_Keypair *keys) {
    BIGNUM *plaintext = rsa_decrypt(ciphertext, keys->private, keys->modulus);

#if 1
    if (BN_cmp(plaintext, B_2) != -1 && BN_cmp(plaintext, B_3) == -1) {
        return true;
    }
    return false;
#else
    unsigned char data[BN_num_bytes(plaintext) + 1];
    BN_bn2binpad(plaintext, data, BN_num_bytes(plaintext) + 1);

    bool rtn = false;

    if (data[0] != 0x00) {
        goto done;
    }

    if (data[1] != 0x02) {
        goto done;
    }
    printf("%s\n", BN_bn2hex(plaintext));

    //Length constraint
    if (BN_num_bytes(plaintext) + 1 < BN_num_bytes(keys->modulus)) {
        goto done;
    }

    //printf("%s\n", BN_bn2hex(plaintext));

    //Check for a zero termination to the padding
    for (int i = 2; i < BN_num_bytes(plaintext) + 1; ++i) {
        if (data[i] == 0x00) {
            rtn = true;
            goto done;
        }
    }
    rtn = false;

done:
    BN_free(plaintext);
    return rtn;
#endif
}

BIGNUM *pkcs1v15_pad(const char *mesg, const size_t len, const RSA_Keypair *key_pair) {
    unsigned char *hex_message = hex_encode((const unsigned char *) mesg, (len / 4) * 3);
    BIGNUM *m = hex_to_bignum((const char *) hex_message);

    size_t random_size = BN_num_bytes(key_pair->modulus) - 3 - BN_num_bytes(m);

    //Fill buffer with random padding bytes
    unsigned char random_data[random_size];
    RAND_bytes(random_data, random_size);

    unsigned char padded_data[3 + random_size + BN_num_bytes(m)];
    //Write the padded data to the buffer
    padded_data[0] = 0x00;
    padded_data[1] = 0x02;
    memcpy(padded_data + 2, random_data, random_size);
    padded_data[random_size + 2] = 0x00;
    BN_bn2bin(m, padded_data + 2 + random_size);

    BIGNUM *plaintext = BN_bin2bn(padded_data, BN_num_bytes(key_pair->modulus), NULL);

    BIGNUM *ciphertext = rsa_encrypt(plaintext, key_pair->public, key_pair->modulus);

    free(hex_message);
    BN_free(m);
    BN_free(plaintext);

    return ciphertext;
}

void generate_constants(const BIGNUM *n) {

    BIGNUM *B = BN_new();
    BN_set_word(B, 2);

    //BN_CTX *ctx = BN_CTX_new();

    //BIGNUM *tmp = BN_new();
    //BN_set_word(tmp, 8 * ((256 + 7) / 8));
    //BN_set_word(tmp, 8 * (32 - 2));
    //BN_exp(B, B, tmp, ctx);

    //BN_CTX_free(ctx);
    //BN_free(tmp);

    //B = 2^8(k-2) where k is modulus num bytes
    BN_lshift(B, B, 8 * (BN_num_bytes(n) - 2) - 1);

    B_2 = BN_dup(B);
    B_3 = BN_dup(B);

    BN_mul_word(B_2, 2);
    BN_mul_word(B_3, 3);

    BN_free(B);

    range_list = checked_calloc(100, sizeof(struct range *));
    range_allocated = 100;
}

void free_constants(void) {
    BN_free(B_2);
    BN_free(B_3);

    for (unsigned int i = 0; i < range_allocated; ++i) {
        if (range_list[i]) {
            BN_free(range_list[i]->a);
            BN_free(range_list[i]->b);
            free(range_list[i]);
        }
    }

    free(range_list);
}

//INDEPENDENTLY VERIFIED WITH KNOWN GOOD SOLUTION
//Generates extra ranges/results though, for some odd reason
void get_range_from_s(const BIGNUM *s, const BIGNUM *n) {
    BIGNUM *calculated_r = BN_new();
    BIGNUM *tmp = BN_new();
    BIGNUM *max_r = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    struct range **new_range_list = checked_calloc(1000, sizeof(struct range *));
    size_t new_range_count = 0;
    size_t new_range_allocated = 1000;

    for (unsigned int i = 0; i < range_count; ++i) {
    //unsigned int i = 0; {
        struct range *elem = range_list[i];

        //calculated r = ((elem->a * s) - 3B + 1) / n
        BN_mul(calculated_r, elem->a, s, ctx);
        BN_sub(calculated_r, calculated_r, B_3);
        BN_add_word(calculated_r, 1);
        //printf("R testing: %s\n", BN_bn2hex(calculated_r));
        BN_div(calculated_r, NULL, calculated_r, n, ctx);

        //printf("R testing: %s\n", BN_bn2hex(n));

        //max_r = ((elem->b * s) - B2) / n
        BN_mul(max_r, elem->b, s, ctx);
        BN_sub(max_r, max_r, B_2);
        BN_div(max_r, NULL, max_r, n, ctx);

        //printf("R2testing: %s\n", BN_bn2hex(max_r));

        for (; BN_cmp(calculated_r, max_r) != 1; BN_add_word(calculated_r, 1)) {
            if (new_range_count == new_range_allocated) {
                new_range_list = checked_realloc(new_range_list, (new_range_allocated + 100) * sizeof(struct range *));
                new_range_allocated += 100;
            }
            struct range *m = checked_malloc(sizeof(struct range));
            new_range_list[new_range_count++] = m;

            m->a = BN_new();
            m->b = BN_new();

            //printf("R result: %s\n", BN_bn2hex(calculated_r));

            //tmp = (2B + rn) / s
            BN_mul(tmp, calculated_r, n, ctx);
            BN_add(tmp, tmp, B_2);
            BN_div(tmp, NULL, tmp, s, ctx);
            BN_add_word(tmp, 1);

            //printf("Range testing a: %s\n", BN_bn2hex(tmp));

            //m->a = max(elem->a, (2B + rn) / s)
            if (BN_cmp(elem->a, tmp) == 1) {
                BN_copy(m->a, elem->a);
            } else {
                BN_copy(m->a, tmp);
            }

            //tmp = (3B - 1 + rn) / s
            BN_mul(tmp, calculated_r, n, ctx);
            BN_add(tmp, tmp, B_3);
            BN_sub_word(tmp, 1);
            BN_div(tmp, NULL, tmp, s, ctx);
            //BN_add_word(tmp, 1);

            //printf("Range testing b: %s\n", BN_bn2hex(tmp));

            //m->b = min(elem->b, (3B - 1 + rn) / s)
            if (BN_cmp(elem->b, tmp) == -1) {
                BN_copy(m->b, elem->b);
            } else {
                BN_copy(m->b, tmp);
            }

            //Range is invalid; remove it
            if (BN_cmp(m->a, B_3) == 1 || BN_cmp(m->b, B_2) == -1 || BN_cmp(m->a, m->b) == 1) {
                printf("Invalid range a: %s\n", BN_bn2hex(m->a));
                printf("Invalid range b: %s\n", BN_bn2hex(m->b));

                BN_free(m->a);
                BN_free(m->b);
                free(m);
                --new_range_count;
                new_range_list[new_range_count] = NULL;
            }
        }
    }

    if (new_range_count == 1) {
        int x = 0;
        x += 7;
        printf("%d\n", x);
    }

    //Free old range list
    for (unsigned int i = 0; i < range_allocated; ++i) {
        if (range_list[i]) {
            BN_free(range_list[i]->a);
            BN_free(range_list[i]->b);
            free(range_list[i]);
        }
    }
    free(range_list);

    //Assign new ranges
    range_list = new_range_list;
    range_count = new_range_count;
    range_allocated = new_range_allocated;

    BN_free(calculated_r);
    BN_free(max_r);
    BN_free(tmp);
    BN_CTX_free(ctx);
}

BIGNUM *generate_initial_s(BIGNUM *ciphertext, const RSA_Keypair *keys) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *test = BN_new();

    BN_div(test, NULL, keys->modulus, B_3, ctx);

    for (;;) {
        BIGNUM *output = rsa_encrypt(test, keys->public, keys->modulus);
        BN_mod_mul(output, output, ciphertext, keys->modulus, ctx);

        if (oracle(output, keys)) {
            BN_free(output);
            //Value is padded correctly
            break;
        }
        BN_free(output);
        BN_add_word(test, 1);
    }
    BN_CTX_free(ctx);
    return test;
}

BIGNUM *generate_next_s(BIGNUM *ciphertext, const RSA_Keypair *keys, const BIGNUM *old_s) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *test = BN_new();

    BN_copy(test, old_s);
    BN_add_word(test, 1);

    for (;;) {
        BIGNUM *output = rsa_encrypt(test, keys->public, keys->modulus);
        BN_mod_mul(output, output, ciphertext, keys->modulus, ctx);

        if (oracle(output, keys)) {
            BN_free(output);
            //Value is padded correctly
            break;
        }
        BN_free(output);
        BN_add_word(test, 1);
    }
    BN_CTX_free(ctx);
    return test;
}

//INITIAL R CALCULATION HAS BEEN VERIFIED USING KNOWN GOOD SOURCE CODE
BIGNUM *generate_new_s(BIGNUM *ciphertext, const RSA_Keypair *keys, const struct range *range, const BIGNUM *s) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *new_s = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *max = BN_new();

    //r = 2 * (((b * s) - 2B) / n)
    BN_mul(r, range->b, s, ctx);
    //printf("Bytes: %d\n", BN_num_bytes(r));
    //printf("R1: %s\n", BN_bn2hex(r));
    //printf("B : %s\n", BN_bn2hex(range->b));
    BN_sub(r, r, B_2);
    //printf("R2: %s\n", BN_bn2hex(r));
    //printf("Bytes: %d\n", BN_num_bytes(r));
    //printf("Bytes: %d\n", BN_num_bytes(keys->modulus));
    BN_div(r, NULL, r, keys->modulus, ctx);
    //printf("Mo: %s\n", BN_bn2hex(keys->modulus));
    BN_mul_word(r, 2);
    //printf("R3: %s\n", BN_bn2hex(r));
    //printf("R4: %s\n", BN_bn2hex(r));
    BN_add_word(r, 1);

    printf("Step 2c values:\n");
    printf("%s\n%s\n%s\n", BN_bn2hex(range->a), BN_bn2hex(range->b), BN_bn2hex(r));

    for (;;BN_add_word(r, 1)) {
        //new_s = (2B + (r * n)) / b
        BN_mul(new_s, r, keys->modulus, ctx);
        BN_add(new_s, new_s, B_2);
        BN_div(new_s, NULL, new_s, range->b, ctx);

        //max = (3B + (r * n)) / a
        BN_mul(max, r, keys->modulus, ctx);
        BN_add(max, max, B_3);
        BN_div(max, NULL, max, range->a, ctx);

        //printf("A %s\na %s\n", BN_bn2hex(B_3), BN_bn2hex(range->a));
        //printf("B %s\nb %s\n", BN_bn2hex(B_2), BN_bn2hex(range->b));

        //printf("ls %s\nus %s\n\n", BN_bn2hex(new_s), BN_bn2hex(max));

        if (BN_cmp(new_s, max) == 1) {
            printf("New S range mismatch\n");
            printf("%s\n%s\n", BN_bn2hex(new_s), BN_bn2hex(max));
            abort();
        }

        //printf("Trying r value: %s\n", BN_bn2hex(r));

        for (; BN_cmp(new_s, max) != 1; BN_add_word(new_s, 1)) {
            //printf("Testing: %s\n", BN_bn2hex(new_s));
            BIGNUM *output = rsa_encrypt(new_s, keys->public, keys->modulus);
            BN_mod_mul(output, output, ciphertext, keys->modulus, ctx);

            //printf("Trying s value: %s\n", BN_bn2hex(new_s));

            if (oracle(output, keys)) {
                BN_free(output);
                //Value is padded correctly
                goto done;
            }
            BN_free(output);
        }
    }

done:
    BN_CTX_free(ctx);
    BN_free(r);
    BN_free(max);
    return new_s;
}

int main(void) {
#if 0
#if 0
   const char *n_str = "132612873667943759709952987787418659308186748087820711824488472839444815304296819509183776818588204467977322651020986774824174771971764867542387710283174319821777732898020166199499557511625594292552518432693889774231592909455038338994172291108945975963304244989245844704242208804056234505929094378066006392239";
    const int s = 43408;
   const char *range_low = "6110192440562944920489062649997431483266761209184421212243067123131175976916130637009646120827403826454760841014727963088833728854759318091888099997006701191343878554523153391201245176314250380554959417110418400024382081940287633297026697267240885168236747844431631609797140152695039512429603976350766318";
   const char *range_high = "6110255633108890295635156180409465983926433094466350031033038004097685101932046593434120470897662031886865675201114549341503109593146974107460151509443558978736751003135168572806761850547085248943558771060626453376243393149672181170333349183460250163816044983813733705143503059763711256620606333627098462";
#else
   const char *n_str = "132612873667943759709952987787418659308186748087820711824488472839444815304296819509183776818588204467977322651020986774824174771971764867542387710283174319821777732898020166199499557511625594292552518432693889774231592909455038338994172291108945975963304244989245844704242208804056234505929094378066006392239";
    const int s = 130222;
   const char *range_low = "6110202025247126844530119201523269056368283108227182836072253144926796916213563581637893951000819855098658822555722216837836875412867656386034844233714458114611709326279904372558107544500555648733238255507553262929341808992982437238976701628082630025925248655281531874299604482840159214105609089997835158";
   const char *range_high = "6110223089752620515678939124179391628626695950882939667990324254270795841884271141316547193831138604475851667408071811653274147756188534366130001826531794070403739914424383454457727177090278552443919405822174687726208665568499357990343560886727484165226642661104651529617407320072246749789618169298191669";
#endif

    BIGNUM *n = NULL;
    BN_dec2bn(&n, n_str);

    BIGNUM *s_old = BN_new();
    BN_set_word(s_old, s);

    generate_constants(n);

    struct range *start = checked_malloc(sizeof(struct range));
    start->a = BN_dup(B_2);
    start->b = BN_dup(B_3);

    range_list[0] = start;
    range_count = 1;

    get_range_from_s(s_old, n);

    printf("Range count: %d\n", range_count);

    for (int i = 0; i < range_count; ++i) {
        printf("Got %s\n    %s\nHas %s\n    %s\n", BN_bn2dec(range_list[i]->a), BN_bn2dec(range_list[i]->b), range_low, range_high);
    }
#else
    const char *e_str = "65537";
    BIGNUM *e = hex_to_bignum(e_str);
#if 1
#if 0
    const char *p_str = "167230636094866282461211664159158428279902699551992447152002026086321450931356694020366071860452874936312114743689156451204955885905421523426919810372766672329365549589557666294538091910136590569719360771818561583316969574158815755289605442067349031803550793473499645742177046498728201139371344588674279678939";
    const char *q_str= "153746015991426629737627279764483089360526745536038013938043722107713599542535853191396561623967198520570205780805436781605500829408932188321165836162114053101365153759076284383142329005938490083741368370827739032497065588280706602245858167496933285469691492972704468586486254156236192774677901155398324342253";
    const char *m_str = "2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000abcd";
#else
    const char *p_str = "313115142601654954062569328755831304743";
    const char *q_str= "255336707253239299888475776540791782543";
    const char *m_str = "200000000000000000000000000000000000000000000000000000000abcd";
#endif
    BIGNUM *p = NULL;
    BN_dec2bn(&p, p_str);
    BIGNUM *q = NULL;
    BN_dec2bn(&q, q_str);
    BIGNUM *m = hex_to_bignum(m_str);

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n = BN_dup(p);
    BN_mul(n, n, q, ctx);

    BIGNUM *et = BN_new();
    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    BN_mul(et, p, q, ctx);

    RSA_Keypair *key_pair = checked_malloc(sizeof(RSA_Keypair));
    key_pair->modulus = n;
    key_pair->public = e;
    key_pair->private = BN_mod_inverse(NULL, e, et, ctx);

    generate_constants(key_pair->modulus);

    BIGNUM *padded = rsa_encrypt(m, key_pair->public, key_pair->modulus);

    if (!oracle(padded, key_pair)) {
        fprintf(stderr, "Padded test did not work\n");
        goto cleanup;
    }
#else
    const RSA_Keypair *key_pair = generate_rsa_keys(e, 256);

    generate_constants(key_pair->modulus);

    const char *message = "kick it, CC";
    BIGNUM *padded = pkcs1v15_pad(message, strlen(message), key_pair);

    if (!oracle(padded, key_pair)) {
        fprintf(stderr, "Padded test did not work\n");
        goto cleanup;
    }
#endif

    //Get initial S
    //Compute first new range using default range
    //while true:
    //Check new range
    //Calculate new s based on the new range
    //Generate new s based on range len
    //Create new range based on s


    //Calculate initial S value
    BIGNUM *s = generate_initial_s(padded, key_pair);
    printf("Initial s value: %s\n", BN_bn2hex(s));

#if 0
    BN_set_word(s, 22626);

    BIGNUM *output = rsa_encrypt(s, key_pair->public, key_pair->modulus);
    BN_mod_mul(output, output, padded, key_pair->modulus, ctx);

    if (oracle(output, key_pair)) {
        BN_free(output);
        //Value is padded correctly
        printf("Padded is good\n");
    } else {
        printf("Padded is bad\n");
    }

    exit(1);

    BN_set_word(s, 22626);
    printf("Corrected s value: %s\n", BN_bn2hex(s));
#endif

    //Create initial range
    struct range *start = checked_malloc(sizeof(struct range));
    start->a = BN_dup(B_2);
    start->b = BN_dup(B_3);
    BN_sub_word(start->b, 1);
    range_list[0] = start;
    range_count = 1;

    get_range_from_s(s, key_pair->modulus);

    for (unsigned int i = 0; i < range_count; ++i) {
        printf("Range element %lu\n", i);
        printf("%s\n%s\n", BN_bn2dec(range_list[i]->a), BN_bn2dec(range_list[i]->b));
    }

    for (;;) {
        //Range is a single number
        if (range_count == 1 && BN_cmp(range_list[0]->a, range_list[0]->b) == 0) {
            printf("End condition found\n");
            goto cleanup;
        }
        BIGNUM *tmp_num;
        if (range_count == 1) {
            printf("Calling new S 2c\n");
            tmp_num = generate_new_s(padded, key_pair, range_list[0], s);
            BN_free(s);
            s = tmp_num;
        } else if (range_count > 1) {
            printf("Calling NEXT S 2b\n");
            tmp_num = generate_next_s(padded, key_pair, s);
            BN_free(s);
            s = tmp_num;
        } else {
            fprintf(stderr, "Range count is zero or negative\n");
            abort();
        }
        printf("New s value: %s\n", BN_bn2hex(s));
        get_range_from_s(s, key_pair->modulus);
    }

#if 0
    uint64_t i = 1;
    for (;;) {
        if (i == 1) {
            s = generate_initial_s(padded, key_pair);

        } else {
            if (range_count > 1) {
                printf("Calling NEXT S\n");
                tmp_num = generate_next_s(padded, key_pair, s);
                BN_free(s);
                s = tmp_num;
            }
        }
        if (range_count == 1) {
            if (BN_cmp(range_list[0]->a, range_list[0]->b) != -1) {
                fprintf(stderr, "Range mismatch\n");
                fprintf(stderr, "%s\n%s\n", BN_bn2hex(range_list[0]->a), BN_bn2hex(range_list[0]->b));
                abort();
            }
            printf("Calling new S\n");
            tmp_num = generate_new_s(padded, key_pair, range_list[0], s);
            BN_free(s);
            s = tmp_num;
        } else {
            fprintf(stderr, "Range count is zero or negative\n");
            abort();
        }
        printf("New s value: %s\n", BN_bn2hex(s));
        get_range_from_s(s, key_pair->modulus);
        printf("New range count: %d\n", range_count);

        //Range is a single number
        if (range_count == 1 && BN_cmp(range_list[0]->a, range_list[0]->b) == 0) {
            printf("End condition found\n");
            break;
        }

        i+= 1;
    }
#endif

cleanup:
    rsa_keypair_free(key_pair);
    BN_free(padded);
    free_constants();
    BN_free(e);

    return EXIT_SUCCESS;
#endif
}
