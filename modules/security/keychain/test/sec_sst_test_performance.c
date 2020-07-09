#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include "keychain.h"

// performance:
// case 1: client: store, get (10000)
// case 2: client1: store, get (10000), client2: store, get(10000)

static int test_sec_sst_performance(int test_times);
static int test_sec_sst_store(char *key, uint8_t *secret, uint32_t secret_len);
static int test_sec_sst_get(char *key);

static void usage()
{
    printf("Usage: sec_sst_test_performance [OPTION]... \n"
           "Security storage service's stress testing program.\n"
           "\n"
           "-p TREAD_NUM    start THREAD_NUM threads\n"
           "-c TEST_NUM     test TEST_NUM times every thread\n"
           "\n"
           "Examples:"
           "sec_sst_test_performance -p 2 -c 10000 start two threads, and every thread run 10000 test.\n");
}

int sst_test_performance(int task_count, int test_count)
{
    pid_t fpid;
    int ret = 0;

    printf("task_count %d, test_count %d\n", task_count, test_count);
    if (task_count == 0 || test_count == 0) {
        printf("Invalid OPTIONS\n");
        return -1;
    }

    for (int i = 0;i < task_count - 1; i ++) {
        fpid = fork();
        if (fpid == 0) {
            printf("child task: %d\n", getpid());
            break;
        } else if (fpid > 0) {
            printf("parent task : %d\n", getpid());
        } else {
            printf("fork child task fail, exit...\n");
            return -1;
        }
    }

    ret = kc_init();
    if (ret) {
        printf("kc init failed\n");
        return -1;
    }

    if (test_sec_sst_performance(test_count)) {
        printf("sec sst performance failed\n");
        return -1;
    }

    kc_destroy();

    return 0;
}

static int test_sec_sst_performance(int test_times) {
    char *basic_key = "test_performance_key";
    char *basic_secret = "test_performance_secret";
    char *key = NULL;
    uint8_t secret[256];
    uint32_t secret_len = 256;
    int success_times = 0;
    int fail_times = 0;
    struct timeval tv_start, tv_now;
    uint32_t i = 0;
    int ret = 0;
    long cost_time = 0;
    key = (char *)malloc(strlen(basic_key) + 20);
    if (key == NULL) {
        printf("malloc key fail\n");
        return -1;
    }
    memset(key, 0, strlen(basic_key) + 20);
    memset(secret, 'a', secret_len - 1);
    secret[secret_len - 1] = 0;
    strncpy((char *)key, basic_key, strlen(basic_key));
    strncpy((char *)secret, basic_secret, strlen(basic_secret));
    sprintf(key + strlen(basic_key), "%08d", getpid());
    sprintf((char *)(secret + secret_len - 13), "%08d", getpid());

    gettimeofday(&tv_start, NULL);
    for(i = 0; i < test_times; i ++) {
        sprintf(key + strlen(basic_key) + 8, "%08d", i + 1);
        sprintf((char *)(secret + secret_len - 5), "%08d", i + 1);
//        printf("store times: %d, key: %s, secret: %s\n", i + 1, key, secret);
        if (test_sec_sst_store(key, secret, secret_len) == 0) {
            success_times += 1;
            printf("8!!!");
        } else {
            printf("times: %d, key: %s, secret: %s ", i + 1, key, secret);
            printf("store fail.\n");
            fail_times += 1;
            break;
        }
    }

    if (success_times != test_times) {
        printf("EEEEEE pid %d test failed EEEEEE \n", getpid());
        ret = -1;
        goto clean;
    }

    gettimeofday(&tv_now, NULL);
    cost_time = (tv_now.tv_sec - tv_start.tv_sec) * 1000000 + (tv_now.tv_usec - tv_start.tv_usec);
    if (success_times != 0) {
        cost_time = cost_time / success_times;
    }

    printf("<<<<<<<<< pid %d test store success av_time %ldus>>>>>>>>>>>>>>\n", getpid(), cost_time);

    success_times = 0;
    fail_times = 0;
    gettimeofday(&tv_start, NULL);
    for(i = 0; i < test_times; i ++) {
        sprintf(key + strlen(key) - 8, "%08d", i + 1);
        if (test_sec_sst_get(key) == 0) {
            success_times += 1;
        } else {
            printf("times: %d, key: %s, secret: %s ", i + 1, key, secret);
            printf("get fail.\n");
            fail_times += 1;
            break;
        }
    }

    if (success_times != test_times) {
        printf("EEEEEE pid %d test failed EEEEEE \n", getpid());
        ret = -1;
        goto clean;
    }
    gettimeofday(&tv_now, NULL);

    cost_time = (tv_now.tv_sec - tv_start.tv_sec) * 1000000 + (tv_now.tv_usec - tv_start.tv_usec);
    if (success_times != 0) {
        cost_time = cost_time / success_times;
    }
    ret = 0;

    printf("<<<<<<<<< pid %d test get success av_time %ldus>>>>>>>>>>>>>>\n", getpid(), cost_time);

    success_times = 0;
    fail_times = 0;
    gettimeofday(&tv_start, NULL);
    for(i = 0; i < test_times; i ++) {
        sprintf(key + strlen(key) - 8, "%08d", i + 1);
#if 1
        if (kc_delete_item(key) == 0) {
#else        
        if (kc_delete_global_item(key) == 0) {
#endif
            success_times += 1;
        } else {
            printf("delete fail.\n");
            fail_times += 1;
            break;
        }
    }

    if (success_times != test_times) {
        printf("EEEEEE pid %d test failed EEEEEE \n", getpid());
        ret = -1;
        goto clean;
    }
    gettimeofday(&tv_now, NULL);

    cost_time = (tv_now.tv_sec - tv_start.tv_sec) * 1000000 + (tv_now.tv_usec - tv_start.tv_usec);
    if (success_times != 0) {
        cost_time = cost_time / success_times;
    }
    ret = 0;

    printf("<<<<<<<<< pid %d test delete success av_time %ldus>>>>>>>>>>>>>>\n", getpid(), cost_time);

clean:
    if (key != NULL) {
        free(key);
        key = NULL;
    }

    return ret;
}

static int test_sec_sst_store(char *key, uint8_t *secret, uint32_t secret_len) {
    uint32_t result = 0;
    uint32_t key_type = 0;
#if 1
    result = kc_add_item(key, secret, secret_len, key_type);
#else
    result = kc_add_global_item(key, secret, secret_len, key_type);
#endif
//    printf("The result is: 0x%08x, secret is %s\n", result, secret);

    return result;
}

static int test_sec_sst_get(char *key) {
    uint8_t secret[1024] = { 0 };
    uint32_t result = 0;
    uint32_t secret_len = 1024;
    uint32_t key_type = 0;
#if 1
    result = kc_get_item(key, secret, &secret_len, &key_type);
    if (result) {
        printf("%s failed the result is: %x\n", __FUNCTION__, result);
        return result;
    }
    
#else
    result = kc_get_global_item(key, secret, &secret_len, &key_type);
    if (result) {
        printf("%s failed the result is: %x\n", __FUNCTION__, result);
        return result;
    }
#endif
//    printf("%s success the secret is: %s\n", __FUNCTION__, secret);

    return result;
}

int main(int argc, char *argv[])
{
    int task_count = 0;
    int test_count = 0;
    int ret = 0;
    int opt = 0;

    while ((opt = getopt(argc, argv, "p:c:h")) != -1) {
        switch(opt) {
        case 'p':
            printf("param p , data is %s\n", optarg);
            task_count = atoi(optarg);
            break;
        case 'c':
            printf("param c , data is %s\n", optarg);
            test_count = atoi(optarg);
            break;
        case 'h':
        default:
            usage();
            return -1;
        }
    }

    printf("task_count %d, test_count %d\n", task_count, test_count);
    if (task_count == 0 || test_count == 0) {
        printf("Invalid OPTIONS\n");
        usage();
        return -1;
    }

    ret = sst_test_performance(task_count, test_count);

    return ret;
}

