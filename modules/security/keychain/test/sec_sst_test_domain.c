#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keychain.h"

uint32_t set_domain_two_time(char *domain1)
{
    uint32_t ret = 0;
    char *domain2 = "domain2";

    ret = kc_set_proc_domain_name(domain1);
    if (ret) {
        printf("set domain name failed\n");
        return ret;
    }

    ret = kc_set_proc_domain_name(domain2);
    if (ret != KC_ERROR_ACCESS_DENIED) {
        printf("the second time set domain name success\n");
        return KC_ERROR_GENERIC;
    }

    return KC_SUCCESS;
}

uint32_t test_proc_store_get()
{
    char *key = "test_proc_key";
    char *secret = "sec_sst_test_proc_store_and_get";
    uint32_t ret = 0;
    kc_key_type_t key_type = KEY_CHAIN_USERDATA;
    uint8_t *out_buf = NULL;
    uint32_t out_buf_len = 0;

    ret = kc_add_item(key, secret, strlen(secret), key_type);
    if (ret) {
        printf("kc add item failed\n");
        return ret;
    }

    key_type = 0;
    ret = kc_get_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_ERROR_SHORT_BUFFER) {
        printf("kc get item size failed ret 0x%x\n", ret);
        return ret;
    }

    out_buf = (uint8_t *)malloc(out_buf_len + 1);
    if (out_buf == NULL) {
        printf("malloc failed\n");
        ret = KC_ERROR_OUT_OF_MEMORY;
        return ret;
    }
    memset(out_buf, 0, out_buf_len + 1);

    ret = kc_get_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_SUCCESS || key_type != KEY_CHAIN_USERDATA) {
        printf("kc get item failed ret 0x%x, key_type\n", ret, key_type);
        goto clean;
    }

    if (out_buf_len != strlen(secret) || memcmp(out_buf, secret, strlen(secret))) {
        ret = KC_ERROR_GENERIC;
        goto clean;
    }
    printf("sec_sst_test_store secret type %d is: %s\n", key_type, out_buf);

clean:
    if (out_buf) {
        free(out_buf);
        out_buf = NULL;
    }

    return ret;
}

uint32_t test_proc_domain_store_get()
{
    char *key = "test_proc_domain_key";
    char *secret = "sec_sst_test_proc_domain_store_and_get";
    uint32_t ret = 0;
    kc_key_type_t key_type = KEY_CHAIN_USERDATA;
    uint8_t *out_buf = NULL;
    uint32_t out_buf_len = 0;

    ret = kc_add_item(key, secret, strlen(secret), key_type);
    if (ret) {
        printf("kc add item failed\n");
        return ret;
    }

    key_type = 0;
    ret = kc_get_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_ERROR_SHORT_BUFFER) {
        printf("kc get item size failed ret 0x%x\n", ret);
        return ret;
    }

    out_buf = (uint8_t *)malloc(out_buf_len + 1);
    if (out_buf == NULL) {
        printf("malloc failed\n");
        ret = KC_ERROR_OUT_OF_MEMORY;
        return ret;
    }
    memset(out_buf, 0, out_buf_len + 1);

    ret = kc_get_item(key, out_buf, &out_buf_len, &key_type);
    if (ret != KC_SUCCESS || key_type != KEY_CHAIN_USERDATA) {
        printf("kc get item failed ret 0x%x, key_type\n", ret, key_type);
        goto clean;
    }

    if (out_buf_len != strlen(secret) || memcmp(out_buf, secret, strlen(secret))) {
        ret = KC_ERROR_GENERIC;
        goto clean;
    }
    printf("sec_sst_test_store secret type %d is: %s\n", key_type, out_buf);

clean:
    if (out_buf) {
        free(out_buf);
        out_buf = NULL;
    }

    return ret;
}

int main(int argc, char *argv[])
{
    uint32_t ret = 0;
    char *domain1 = NULL;
    char *default_domain = "default_domain";

    ret = kc_init();
    if (ret) {
        printf("kc init failed\n");
        return ret;
    }

    if (argc > 1) {
        domain1 = argv[1];
    } else {
        domain1 = default_domain;
    }

    ret = test_proc_store_get();
    if (ret) {
        printf("test proc store and get failed 0x%x\n", ret);
        goto clean;
    }

    ret = set_domain_two_time(domain1);
    if (ret) {
        printf("test set domain two time failed 0x%x\n", ret);
        goto clean;
    }

    ret = test_proc_domain_store_get();
    if (ret) {
        printf("test proc domain store and get failed 0x%x\n", ret);
        goto clean;
    }

    printf("<<<<<<<< sec sst domain test success >>>>>>>>>>>>>>>\n");

clean:
    kc_destroy();

    return ret;
}

