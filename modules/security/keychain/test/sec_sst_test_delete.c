#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keychain.h"

uint32_t test_delete_proc_item()
{
    char *key = "test_delete_proc_key";
    char *secret = "sec_sst_test_delete_proc_secret";
    uint32_t ret = 0;
    kc_key_type_t key_type = KEY_CHAIN_USERDATA;
    uint8_t out_buf[1024];
    uint32_t out_buf_len = 1024;

    ret = kc_init();
    if (ret) {
        printf("kc init failed\n");
        return ret;
    }

    ret = kc_add_item(key, secret, strlen(secret), key_type);
    if (ret) {
        printf("kc add item failed\n");
        goto clean1;
    }

    key_type = 0;
    ret = kc_get_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_SUCCESS || key_type != KEY_CHAIN_USERDATA ||
        out_buf_len != strlen(secret) ||
        memcmp(out_buf, secret, strlen(secret))) {
        printf("kc get item failed ret 0x%x, key_type\n", ret, key_type);
        ret = KC_ERROR_GENERIC;
        goto clean1;
    }

    printf("sec_sst_test_store secret type %d is: %s\n", key_type, out_buf);

    ret = kc_delete_item(key);
    if (ret) {
        printf("kc delete item failed ret 0x%x\n", ret);
        goto clean1;
    }

    ret = kc_get_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_ERROR_ITEM_NOT_FOUND) {
        printf("kc get deleted item failed ret 0x%x\n", ret);
        ret = KC_ERROR_GENERIC;
        goto clean1;
    } else {
        ret = KC_SUCCESS;
    }

clean1:
    kc_destroy();

    return ret;
}

uint32_t test_delete_domain_item()
{
    char *key = "test_delete_domain_key";
    char *secret = "sec_sst_test_delete_domain_secret";
    uint32_t ret = 0;
    kc_key_type_t key_type = KEY_CHAIN_USERDATA;
    uint8_t out_buf[1024];
    uint32_t out_buf_len = 1024;
    char *domain_name = "test_delete_domain";

    ret = kc_init();
    if (ret) {
        printf("kc init failed\n");
        return ret;
    }

    ret = kc_set_proc_domain_name(domain_name);
    if (ret) {
        printf("set domain name failed\n");
        return ret;
    }

    ret = kc_add_item(key, secret, strlen(secret), key_type);
    if (ret) {
        printf("kc add item failed\n");
        goto clean1;
    }

    key_type = 0;
    ret = kc_get_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_SUCCESS || key_type != KEY_CHAIN_USERDATA ||
        out_buf_len != strlen(secret) ||
        memcmp(out_buf, secret, strlen(secret))) {
        printf("kc get item size failed ret 0x%x\n", ret);
        ret = KC_ERROR_GENERIC;
        goto clean1;
    }

    printf("sec_sst_test_store secret type %d is: %s\n", key_type, out_buf);

    ret = kc_delete_item(key);
    if (ret) {
        printf("kc delete item failed ret 0x%x\n", ret);
        goto clean1;
    }

    ret = kc_get_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_ERROR_ITEM_NOT_FOUND) {
        printf("kc get deleted item failed ret 0x%x\n", ret);
        ret = KC_ERROR_GENERIC;
        goto clean1;
    } else {
        ret = KC_SUCCESS;
    }

clean1:
    kc_destroy();

    return ret;
}

int main()
{
    uint32_t ret = 0;

    ret = test_delete_proc_item();
    if (ret) {
        printf("test delete proc item failed 0x%x\n", ret);
        return -1;
    }

    ret = test_delete_domain_item();
    if (ret) {
        printf("test delete domain item failed 0x%x\n", ret);
        return -1;
    }
    printf("<<<<<<<<test delete success>>>>>>>>>>>>\n");

    return 0;
}
