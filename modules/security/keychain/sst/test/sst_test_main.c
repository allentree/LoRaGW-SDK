/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include "sst_test.h"
#include "sst.h"
#if IROT_SUPPORT
#include "irot.h"
#endif

int sst_test_create_file(char *file_name, uint32_t over_w_flag)
{
    uint32_t ret = 0;
    uint8_t data[35] = {0x11,0x02,0x03,0x4,0x05,0x06,0x07,0x08,
                        0x21,0x02,0x03,0x4,0x05,0x06,0x07,0x08,
                        0x31,0x02,0x03,0x4,0x05,0x06,0x07,0x08,
                        0x41,0x02,0x03,0x4,0x05,0x06,0x07,0x08,
                        0x02,0x03,0x4};

    printf("create file:%s, overwrite[%d]\n", file_name, over_w_flag);

    ret = sst_add_item(file_name, data, sizeof(data), SST_TYPE_USERDATA, over_w_flag);
    if( 0 != ret){
        printf("%s %d: error[%x]\n",__FUNCTION__, __LINE__, ret);
        return ret;
    }

    printf("<<<<<<<<<<<<<<sst add item success>>>>>>>>>>>>>>>>>>>>>>\n");
    return 0;
}

int sst_test_read_file(char *file_name)
{
    uint32_t ret = 0;
    uint32_t data_size = 0;
    uint8_t *p_out_data = NULL;

    uint32_t type = SST_TYPE_NONE;

    printf("read file:%s \n",file_name);
    ret = sst_get_item(file_name, NULL, &data_size, &type);
    if(ret != SST_ERROR_SHORT_BUFFER) {
        printf("%s %d: error[%x]\n",__FUNCTION__, __LINE__, ret);
        return ret;
    }

    p_out_data = malloc(data_size);
    if(!p_out_data){
        printf("%s %d: error[%x]\n",__FUNCTION__, __LINE__, ret);
        return -1;
    }
    memset(p_out_data, 0, data_size);

    ret = sst_get_item(file_name, p_out_data, &data_size, &type);
    if( 0 != ret){
        printf("%s %d: error[%x]\n",__FUNCTION__, __LINE__, ret);
        goto clean;
    }

    printf("\nsst read type[%d] file data:\n", type);
    printf("<<<<<<< test get success>>>>>>>>>>>>>>>>>\n");
   // _sst_dump_data(p_out_data, data_size);
clean:
    free(p_out_data);
    p_out_data = NULL;

    return ret;
}

int init()
{
    uint32_t ret = 0;
    int fret = 0;
    DIR *dir = NULL;

    ret = sst_init();
    if(0 != ret){
        printf("%s %d: error[%x]\n",__FUNCTION__, __LINE__, ret);
        return -1;
    }

    //mkdir data folder ./data
    dir = opendir("./data");
    if (NULL == dir) {
        fret = mkdir("./data", S_IRWXU |
                     S_IRGRP | S_IROTH | S_IXGRP | S_IXOTH);
        if (fret < 0) {
            printf("mkdir failed errno is %d\n", errno);
            return -1;
        }
    } else {
        closedir(dir);
    }

    //mkdir ./data/.sst
    dir = opendir("./data/.sst");
    if (NULL == dir) {
        fret = mkdir("./data/.sst", S_IRWXU |
                     S_IRGRP | S_IROTH | S_IXGRP | S_IXOTH);
        if (fret < 0) {
            printf("mkdir failed errno is %d\n", errno);
            return -1;
        }
    } else {
        closedir(dir);
    }

    //mkdir ./data/sst
    dir = opendir("./data/sst");
    if (NULL == dir) {
        fret = mkdir("./data/sst", S_IRWXU |
                     S_IRGRP | S_IROTH | S_IXGRP | S_IXOTH);
        if (fret < 0) {
            printf("mkdir failed errno is %d\n", errno);
            return -1;
        }
    } else {
        closedir(dir);
    }

    return 0;
}

void help()
{
    printf("help: \n");
//    printf("./sst_test add                   test add item\n");
//    printf("./sst_test get                   test get item\n");
    printf("./sst_test basic                 test basic add and get\n");
    printf("./sst_test data_mig              test data migration\n");
//    printf("./sst_test sst_mig               test sst migration\n");
    printf("./sst_test stress_test           test sst migration\n");
//    printf("./sst_test perf task_count test_count    test sst migration\n");
}

int main(int argc, char *argv[])
{
    int ret = 0;

    if(argc <= 1 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "help")) {
        help();
        return 0;
    }

    //cmd = strtol(argv[1], NULL, 16);
    printf("the cmd [%s]\n", argv[1]);

#if IROT_SUPPORT
    irot_init();
#endif

    if (init()) {
        printf("init fialed\n");
        ret = -1;
        goto clean;
    }

    if (strcmp(argv[1], "add") == 0) {
        sst_test_create_file("./test_add", 1);
    } else if (strcmp(argv[1], "get") == 0) {
        sst_test_read_file("./test_add");
    } else if(strcmp(argv[1], "basic") == 0) {
        sec_sst_basic_test();
#if CONFIG_DATA_MIGRATION
    } else if (strcmp(argv[1], "data_mig") == 0) {
        sst_test_migration();
#endif /* CONFIG_DATA_MIGRATION */
#if CONFIG_SST_MIGRATION
    } else if (strcmp(argv[1], "sst_mig") == 0) {
        sst_file_mig_whole_test();
#endif /* CONFIG_SST_MIGRATION */
#if !IROT_SUPPORT
    } else if (strcmp(argv[1], "perf") == 0) {
        int task_count = atoi(argv[2]);
        int test_count = atoi(argv[3]);
        int ret = 0;
        ret = sst_test_performance(task_count, test_count);
        if (ret) {
            printf("test performance failed\n");
            ret = -1;
        }
#endif
    } else if (strcmp(argv[1], "stress_test") == 0) {
        int ret = 0;
        uint32_t i = 0;

        for (;;) {
            ret = sst_test_performance(1, 100);
            if (ret) {
                printf("test performance failed\n");
                ret = -1;
                goto clean;
            }
            i++;
            printf("<<<<<<<< test %d success >>>>>>\n", i);
        }
    }

clean:
#if IROT_SUPPORT
    irot_destroy();
#endif
    return ret;
}

