#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"

uint8_t key[32] = "IWf8d2vXAfuyORMJ";
int ishexstr = 1;

static int test_encrypt_ecb(uint8_t* in, uint8_t* out)
{
    uint8_t input[512] = {0};
    struct AES_ctx ctx;
    int i = 0;
    int len = 0;
    int size = 0;
    int padding = 0;

    if ((in == NULL) || (out == NULL) || (strlen(in) <= 0)) {
        printf("param is invalid");
        return -1;
    }

    printf("key: %s\n", key);
    printf("ishexstr: %d\n", ishexstr);

    if (ishexstr == 1) {
        if ((strlen(in) % 2) != 0) {
            printf("input data is invalid");
            return -1;
        }
        
        memset(input, 0, sizeof(input));
        for (i = 0; i < strlen(in); i = i + 2) {
            sscanf(in + i, "%02hhx", &input[i/2]);
        }
        len = strlen(in) / 2;
    } else {
        memset(input, 0, sizeof(input));
        strcpy(input, in);
        len = strlen(in);
    }
    padding = 16 - (len % 16);
    size = len + padding;

    printf("len: %d, padding: %d, size: %d, in: %s\n", len, padding, size, in);
    if (padding != 0) {
        for (i = len; i < size; i++) {
            input[i] = 0;
        }
    }

    #if 1
    printf("size: %d, input data: ", size);
    for(i = 0; i < size; i++)
    {
        printf("%02x", input[i]);
    }
    printf("\n");
    #endif

    AES_init_ctx(&ctx, key);
    for(i = 0; i < size / 16; i++) {
        AES_ECB_encrypt(&ctx, input + 16 * i);
    }
    
    #if 1
    printf("size: %d, out data: ", size);
    for(i = 0; i < size; i++) {
        printf("%02x", input[i]);
    }
    printf("\n");
    #endif

    for(i = 0; i < size; i++) {
        sprintf((char *)(out + 2 * i), "%02x", input[i]);
    }
    printf("encrypt, size: %d, out: %s\n", size, out);

    return 0;
}

static int test_decrypt_ecb(uint8_t* in, uint8_t* out)
{
    uint8_t input[512] = {0};
    struct AES_ctx ctx;
    int i = 0;
    int size = 0;

    if ((in == NULL) || (out == NULL) || (strlen(in) <= 0)) {
        printf("param is invalid");
        return -1;
    }

    if ((strlen(in) % 16) != 0) {
        printf("input data is invalid");
        return -1;
    }

    printf("key: %s\n", key);
    printf("ishexstr: %d\n", ishexstr);

    size = strlen(in) / 2;
    memset(input, 0, sizeof(input));
    for (i = 0; i < strlen(in); i = i + 2) {
        sscanf(in + i, "%02hhx", &input[i/2]);
    }

    printf("size: %d, in: %s\n", size, in);

    #if 1
    printf("size: %d, input data: ", size);
    for(i = 0; i < size; i++)
    {
        printf("%02x", input[i]);
    }
    printf("\n");
    #endif

    AES_init_ctx(&ctx, key);
    for(i = 0; i < size / 16; i++) {
        AES_ECB_decrypt(&ctx, input + 16 * i);
    }

    #if 1
    printf("size: %d, out data: ", size);
    for(i = 0; i < size; i++)
    {
        printf("%02x", input[i]);
    }
    printf("\n");
    #endif

    if (ishexstr == 1) {
        for(i = 0; i < size; i++) {
            if (input[i] != 0) {
                sprintf((char *)(out + 2 * i), "%02x", input[i]);
            }
        }
    } else {
        memcpy(out, input, size);
    }
    printf("decrypt, size: %d, out: %s\n", size, out);

    return 0;
}

int main(int argc, char **argv)
{
    uint8_t in[512]  = {0};
    uint8_t out[512] = {0};

    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));

    printf("aes encrypt\n");

    if (argc > 3) {
        strcpy(key, argv[1]);
        strcpy(in, argv[2]);
        sscanf(argv[3], "%d", &ishexstr);
    } else if (argc > 2) {
        strcpy(key, argv[1]);
        strcpy(in, argv[2]);
        printf("use hexstr\n");
    } else if (argc > 1) {
        strcpy(in, argv[1]);
        printf("use default key and hexstr\n");
    }
    else {
        printf("iput param error.\n");
        return 0;
    }

    test_encrypt_ecb(in, out);
    printf("\n");
    printf("aes decrypt\n");
    test_decrypt_ecb(out, in);

    return 0;
}

