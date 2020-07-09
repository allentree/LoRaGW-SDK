#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sst.h"

char *file_name = "./data/.sst/sst_test_migration_file";
char *file_name2 = "./data/sst/sst_test_migration_file";
char *file_wrong_name = "./data/.sst/sst_test_migration_wrong_file";

char *mig_f_path = "/home/wucd/data/mig";

int sst_test_mig_file_short()
{
    uint8_t *key = NULL;
    uint32_t key_len = 0;
    char *data = "sst_test_migration_file";
    uint32_t data_len = strlen(data) + 1;
    uint32_t ret = 0;
    uint8_t get_data[100] = { 0 };
    uint32_t get_data_len = 100;
    uint32_t type = 0;

    ret = sst_add_item(file_name, (uint8_t *)data, data_len, SST_TYPE_USERDATA, 1);
    if (ret) {
        printf("add item failed\n");
        return -1;
    }

    sst_mig_set_file_path(mig_f_path);
    ret = sst_mig_get_file(file_name, NULL, &key_len);
    if(SST_ERROR_SHORT_BUFFER != ret || key_len != SST_MIGRATION_KEY_LEN) {
        printf("%s %d: error[%x]\n",__FUNCTION__, __LINE__, ret);
        return -1;
    }

    key = malloc(key_len);
    if (!key) {
        printf("malloc key failed\n");
        return -1;
    }

    sst_mig_set_file_path(mig_f_path);
    ret = sst_mig_get_file(file_name, key, &key_len);
    if(ret || key_len != SST_MIGRATION_KEY_LEN) {
        printf("%s %d: ret 0x%x, key_len %d\n",
                __FUNCTION__, __LINE__, ret, key_len);
        ret = -1;
        goto clean;
    }

    sst_mig_set_file_path(mig_f_path);
    ret = sst_mig_store_file(file_name2, key, key_len);
    if (ret) {
        printf("sst migration store file failed 0x%x\n", ret);
        ret = -1;
        goto clean;
    }

    ret = sst_get_item(file_name2, get_data, &get_data_len, &type);
    if (ret || get_data_len != data_len || type != SST_TYPE_USERDATA) {
        printf("get item failed\n");
        ret = -1;
        goto clean;
    }

    if (memcmp(get_data, data, data_len)) {
        printf("get wrong item\n");
        ret = -1;
        goto clean;
    }

    printf("get right item %s\n", get_data);
    ret = 0;

clean:
    if (key) {
        free(key);
        key = NULL;
    }
    return ret;
}

int sst_test_mig_wrong_file_name()
{
    uint32_t ret = 0;
    uint8_t mig_key[18] = {0};
    uint32_t key_len = 18;

    printf("\nsst migration file\n");

    sst_mig_set_file_path(mig_f_path);
    ret = sst_mig_get_file(file_name, mig_key, &key_len);
    if(ret || key_len != SST_MIGRATION_KEY_LEN) {
        printf("%s %d: error[%x]\n",__FUNCTION__, __LINE__, ret);
        return -1;
    }
    printf("\nsst migration file key:\n");
    //_sst_dump_data(mig_key, key_len);

    sst_mig_set_file_path(mig_f_path);
    ret = sst_mig_store_file(file_wrong_name, mig_key, key_len);
    if(!ret) {
        printf("%s %d: error[%x]\n",__FUNCTION__, __LINE__, ret);
        return -1;
    }
    printf("migration store file failed 0x%x\n", ret);

    return 0;
}

int sst_test_mig_wrong_mig_path()
{
    uint32_t ret = 0;
    uint8_t mig_key[16] = {0};
    uint32_t key_len = 16;
    char *path1 = "/usr/.sst";

    sst_mig_set_file_path(path1);
    ret = sst_mig_get_file(file_name, mig_key, &key_len);
    if(!ret || key_len != SST_MIGRATION_KEY_LEN) {
        printf("%s %d: error[%x]\n",__FUNCTION__, __LINE__, ret);
        return -1;
    }

    ret = sst_mig_store_file(file_name, mig_key, key_len);
    if(!ret || key_len != SST_MIGRATION_KEY_LEN) {
        printf("%s %d: error[%x]\n",__FUNCTION__, __LINE__, ret);
        return -1;
    }

    return 0;
}

int sst_file_mig_whole_test()
{
    int ret = 0;

    ret = sst_test_mig_file_short();
    if (ret) {
        printf("test mig file short failed\n");
        return -1;
    }
    printf("<<<<<<<<<test mig file short success>>>>>>>\n");

    ret = sst_test_mig_wrong_file_name();
    if (ret) {
        printf("test mig wrong file name failed\n");
        return -1;
    }
    printf("<<<<<<<test mig wrong file name success>>>>>>\n");

    ret = sst_test_mig_wrong_mig_path();
    if (ret) {
        printf("test mig wrong mig file path failed\n");
        return -1;
    }
    printf("<<<<<<<test mig wrong mig path success>>>>>>\n");
    printf("<<<<<<<test all sst migration testcase success>>>>>>\n");

    return 0;
}

