#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keychain.h"

// two client
// case 1: store: client1(key) get: client1(key)
int test_case1(){
    uint32_t ret = 0;
    char *key = "test_key";
    char *secret = "global_test_string";
    kc_key_type_t key_type = KEY_CHAIN_USERDATA;
    uint8_t *out_buf = NULL;
    uint32_t out_buf_len = 0;


    ret = kc_init();
    if (ret) {
        printf("kc init failed\n");
        return ret;
    }

    ret = kc_add_global_item(key, secret, strlen(secret), key_type);
    if (ret) {
        printf("kc add item failed!, ret %d!!\n", ret);
        goto clean1;
    }

    key_type = 0;
    ret = kc_get_global_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_ERROR_SHORT_BUFFER) {
        printf("kc get item size failed ret 0x%x\n", ret);
        goto clean1;
    }

    out_buf = (uint8_t *)malloc(out_buf_len + 1);
    if (out_buf == NULL) {
        printf("malloc failed\n");
        ret = KC_ERROR_OUT_OF_MEMORY;
        goto clean1;
    }
    memset(out_buf, 0, out_buf_len + 1);

    ret = kc_get_global_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_SUCCESS || key_type != KEY_CHAIN_USERDATA) {
        printf("kc get item failed ret 0x%x, key_type\n", ret, key_type);
        goto clean2;
    }
    printf("sec_sst_test_store secret type %d is: %s\n", key_type, out_buf);
    printf("test case 1 : add and get global data done!!!\n");
clean2:
    if (out_buf) {
        free(out_buf);
        out_buf = NULL;
    }
clean1:
    kc_destroy();

    return ret;

}

int test_case2(){
    uint32_t ret = 0;
    char *key = "test_key";
    char *secret = "global_test_string";
    kc_key_type_t key_type = KEY_CHAIN_USERDATA;
    uint8_t *out_buf = NULL;
    uint32_t out_buf_len = 0;


    ret = kc_init();
    if (ret) {
        printf("kc init failed\n");
        return ret;
    }
    key_type = 0;
    ret = kc_get_global_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_ERROR_SHORT_BUFFER) {
        printf("kc get item size failed ret 0x%x\n", ret);
        goto clean1;
    }

    out_buf = (uint8_t *)malloc(out_buf_len + 1);
    if (out_buf == NULL) {
        printf("malloc failed\n");
        ret = KC_ERROR_OUT_OF_MEMORY;
        goto clean1;
    }
    memset(out_buf, 0, out_buf_len + 1);
    ret = kc_get_global_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_SUCCESS || key_type != KEY_CHAIN_USERDATA) {
        printf("kc get item failed ret 0x%x, key_type\n", ret, key_type);
        goto clean2;
    }

    printf("test case 2 : get the serect %s !!!\n", out_buf);
    ret = kc_delete_global_item(key);
    if(ret != KC_SUCCESS) {
        printf("kc get item failed ret 0x%x, key_type\n", ret, key_type);
        goto clean2;
    }
    ret = kc_get_global_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_ERROR_ITEM_NOT_FOUND) {
        printf("kc delete item failed!!\n");
        goto clean2;
    }

    printf("test case 2 : delete the key %s !!!\n", key);

clean2:
    if (out_buf) {
        free(out_buf);
        out_buf = NULL;
    }
clean1:
    kc_destroy();

    return ret;

}
#define TEST_LOOP 10000
int test_case3()
{
    uint32_t ret = 0;
    char *key = "test_key";
    char *secret = "global_test_secret_string";
    kc_key_type_t key_type = KEY_CHAIN_USERDATA;

    uint32_t out_buf_len = 0;

    char test_key[64] = {0};
    char test_secret[256] = {0};
    int i = 0;

    ret = kc_init();
    if (ret) {
        printf("kc init failed\n");
        return ret;
    }

    key_type = KEY_CHAIN_USERDATA;
    
    for(i = 0; i < TEST_LOOP; i++) {
        sprintf(test_key, "%s_%d", key , i);
        sprintf(test_secret, "%s_%d", secret , i);
        ret = kc_add_global_item(test_key, test_secret, strlen(test_secret), key_type);
        if (ret) {
            printf("kc add item failed!, ret %d!!\n", ret);
            goto clean1;
        }
    }

    printf("test case 3 : add global data done !!!\n", key);

    memset(test_secret, 0 , sizeof(test_secret));
    
    for(i = 0; i < TEST_LOOP; i++) {
        sprintf(test_key, "%s_%d", key , i);
        char tmp[256];
        sprintf(tmp,  "%s_%d", secret , i);
        memset(test_secret, 0 , sizeof(test_secret));
        out_buf_len = sizeof(test_secret);
        ret = kc_get_global_item(test_key, test_secret, &out_buf_len, &key_type);
        if(ret) {
            printf("kc get item failed!, ret %d!!\n", ret);
            goto clean1;
        }
        if(key_type != KEY_CHAIN_USERDATA || strcmp(tmp,test_secret)) {
            printf("kc get item error!!!\n");
        }
    }
    printf("test case 3 : get global data done !!!\n", key);

    for(i = 0; i < TEST_LOOP; i++) {
        sprintf(test_key, "%s_%d", key , i);
        ret = kc_delete_global_item(test_key);
        if(ret) {
            printf("kc delete item failed!, ret %d!!\n", ret);
            goto clean1;
        }
    }
        printf("test case 3 : delete global data done !!!\n", key);
clean1:
    kc_destroy();

    return ret;

}

uint32_t main()
{
    uint32_t ret = 0;
    ret = test_case1();
    printf("test case 1 ret %d !\n", ret);

    ret = test_case2();
    printf("test case 2 ret %d !\n", ret);

    ret = test_case3();
    printf("test case 3 ret %d !\n", ret);
    return ret;
}


