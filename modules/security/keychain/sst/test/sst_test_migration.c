#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sst.h"

static void _dump_data(char *name, uint8_t *data, uint32_t len)
{
    uint32_t i;
    printf("name is %s, len is %d\n", name, len);

    for (i = 0; i < (len - len % 8); i += 8) {
        printf("%s:  0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x,\n",
                          name, data[i+0], data[i+1], data[i+2], data[i+3],
                          data[i+4], data[i+5], data[i+6], data[i+7]);
    }

    while(i < len) {
        printf("%s: %02x\n", name, data[i++]);
    }

    return;
}

uint32_t test_enc_dec_short_buffer()
{
    char *file_path = "./data/test_enc_dec_short";
    uint8_t *key = NULL;
    uint32_t key_len = 0;
    char *data = "sec_sst_test_store_secret";
    uint32_t ret = 0;
    uint8_t *dec_data = NULL;
    uint32_t dec_len = 0;

    ret = sst_encrypt_data((uint8_t *)data, strlen(data), file_path, key, &key_len);
    if (ret != SST_ERROR_SHORT_BUFFER) {
        printf("kc encrypt data get key len failed\n");
        return ret;
    }

    key = (uint8_t *)malloc(key_len);
    if (key == NULL) {
        printf("malloc failed\n");
        return SST_ERROR_OUT_OF_MEMORY;
    }
    memset(key, 0, key_len);
    ret = sst_encrypt_data((uint8_t *)data, strlen(data), file_path, key, &key_len);
    if (ret) {
        printf("kc encrypt data failed ret 0x%x\n", ret);
        goto clean;
    }
    _dump_data("encrypt key is :", key, key_len);

    ret = sst_decrypt_data(file_path, key, key_len, dec_data, &dec_len);
    if (ret != SST_ERROR_SHORT_BUFFER) {
        printf("kc get decrypt data size failed\n");
        goto clean;
    }
    dec_data = malloc(dec_len + 1);
    if (dec_data == NULL) {
        printf("malloc failed\n");
        goto clean;
    }
    memset(dec_data, 0, dec_len + 1);
    ret = sst_decrypt_data(file_path, key, key_len, dec_data, &dec_len);
    if (ret) {
        printf("kc decrypt data failed ret 0x%x\n", ret);
        goto clean1;
    }

    if (dec_len != strlen(data) ||
        memcmp(dec_data, data, dec_len)) {
        printf("get wrong data\n");
    }

    printf("<<<< test enc dec short buffer success data: %s >>>>\n", dec_data);

clean1:
    if (dec_data) {
        free(dec_data);
        dec_data = NULL;
    }
clean:
    if (key) {
        free(key);
        key = NULL;
    }

    return ret;
}

uint32_t test_enc_dec()
{
    char *file_path = "./data/test_enc_dec";
    char *data = "sec_sst_test_migration_enc_dec";
    uint32_t ret = 0;
    uint8_t dec_data[256];
    uint32_t dec_len = 256;
    uint8_t key[32];
    uint32_t key_len = 32;

    ret = sst_encrypt_data((uint8_t *)data, strlen(data), file_path, key, &key_len);
    if (ret) {
        printf("kc encrypt data failed\n");
        return ret;
    }

    memset(dec_data, 0, dec_len);
    ret = sst_decrypt_data(file_path, key, key_len, dec_data, &dec_len);
    if (ret) {
        printf("kc decrypt data failed 0x%x\n", ret);
        return ret;
    }

    printf("<<<<test enc dec success data: %s >>>>\n", dec_data);
    return ret;
}

//test that file path parent is not exist
uint32_t test_enc_folder_parent_not_exist()
{
    char *file_path = "./data_test1/test1/test_enc_folder_parent_not_exist";
    char *data = "sec_sst_test_enc_folder_parent_not_exist";
    uint32_t ret = 0;
    uint8_t key[32];
    uint32_t key_len = 32;

    ret = sst_encrypt_data((uint8_t *)data, strlen(data), file_path, key, &key_len);
    if (!ret) {
        printf("kc encrypt folder parent not exist failed 0x%x\n", ret);
        return ret;
    } else {
        printf("<<<< kc enc folder parent not exist success >>>>\n");
        return SST_SUCCESS;
    }

    return ret;
}

//test that file path parent is not exist
uint32_t test_enc_folder_not_exist()
{
    char *file_path = "./data1/test_enc_folder_not_exist";
    char *data = "sec_sst_test_enc_folder_not_exist";
    uint32_t ret = 0;
    uint8_t dec_data[256];
    uint32_t dec_len = 256;
    uint8_t key[32];
    uint32_t key_len = 32;

    ret = sst_encrypt_data((uint8_t *)data, strlen(data), file_path, key, &key_len);
    if (ret) {
        printf("kc encrypt data failed 0x%x\n", ret);
        return ret;
    }

    ret = sst_decrypt_data(file_path, key, key_len, dec_data, &dec_len);
    if (ret) {
        printf("kc decrypt data failed 0x%x\n", ret);
        return ret;
    }

    if (memcmp(data, dec_data, dec_len)) {
        printf("decrypt wrong data\n");
        return SST_ERROR_GENERIC;
    }

    printf("<<<< test enc dec success data: %s >>>>\n", dec_data);

    return ret;
}

uint32_t test_dec_not_exist()
{
    char *file_path = "./data/test_dec_not_exist";
    char *data = "sec_sst_test_migration_dec_not_exist";
    uint32_t ret = 0;
    uint8_t dec_data[256];
    uint32_t dec_len = 256;
    uint8_t key[32];
    uint32_t key_len = 32;

    ret = sst_encrypt_data((uint8_t *)data, strlen(data), file_path, key, &key_len);
    if (ret) {
        printf("kc test dec not exist encrypt data failed\n");
        return ret;
    }

    memset(dec_data, 0, dec_len);

    //start to dec not exist item
    file_path = "./data/test_enc_dec_not_exist_1";
    ret = sst_decrypt_data(file_path, key, key_len, dec_data, &dec_len);
    if (ret != SST_ERROR_ITEM_NOT_FOUND)  {
        printf("kc test decrypt item not exist failed 0x%x\n", ret);
        return ret;
    } else {
        printf("<<<< kc test decrypt item not exist success >>>>\n");
        return SST_SUCCESS;
    }

    return ret;
}

uint32_t test_enc_access_denied()
{
    char *file_path = "/usr/data/test_enc_access_denied";
    char *data = "sec_sst_test_access_denied";
    uint32_t ret = 0;
    uint8_t key[32];
    uint32_t key_len = 32;

    ret = sst_encrypt_data((uint8_t *)data, strlen(data), file_path, key, &key_len);
    if (ret != SST_ERROR_ACCESS_DENIED) {
        printf("kc test enc access denied failed 0x%x\n", ret);
        return ret;
    } else {
        printf("<<<< kc test enc access denied success >>>>\n");
        return SST_SUCCESS;
    }

    return ret;
}

int sst_test_migration()
{
    uint32_t ret = 0;

    if (sst_init()) {
        printf("test migration kc init failed\n");
        return -1;
    }

    ret = test_enc_dec();
    if (ret) {
        printf("test enc dec failed 0x%x\n", ret);
        goto clean;
    }

    ret = test_enc_dec_short_buffer();
    if (ret) {
        printf("test enc dec short buffer failed 0x%x\n", ret);
        goto clean;
    }

    ret = test_dec_not_exist();
    if (ret) {
        printf("test dec not exist failed\n");
        goto clean;
    }

#if 0
    ret = test_enc_access_denied();
    if (ret) {
        printf("test enc access denied failed\n");
        goto clean;
    }

    ret = test_enc_folder_parent_not_exist();
    if (ret) {
        printf("test enc folder folder not exist failed 0x%x\n", ret);
        goto clean;
    }

    ret = test_enc_folder_not_exist();
    if (ret) {
        printf("test enc folder not exist failed 0x%x\n", ret);
        goto clean;
    }
#endif
    printf("<<<< test data migration all test success >>>>>>\n");

clean:
//    sst_destroy();

    return ret;
}
