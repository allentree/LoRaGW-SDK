#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include "keychain.h"

static void test_sec_sst(char *key, char *secret, uint8_t **out_buf, uint32_t *out_len);
static void usage();
static void *test_thread(void *arg);

int main(int argc, char **argv)
{
    int opt;
    int pthread_count = 1;
    pthread_t *thread_id;

    while ((opt = getopt(argc, argv, "p:h")) != -1) {
        switch(opt) {
        case 'p':
            printf("param p , data is %s\n", optarg);
            pthread_count = atoi(optarg);
            break;
        case 'h':
        default:
            usage();
            return -1;
        }
    }

    printf("pthread_count %d\n", pthread_count);
    if (pthread_count == 0) {
        printf("Invalid OPTIONS\n");
        usage();
        return -1;
    }

    thread_id = (pthread_t *)malloc(pthread_count * sizeof(pthread_t));
    if (thread_id == NULL) {
        printf("pthread_id malloc fail.\n");
        return -1;
    }

    if (kc_init()) {
        printf("kc init failed\n");
        return -1;
    }

    for (int i = 0;i < pthread_count; i ++) {
        pthread_create(&thread_id[i], NULL, test_thread, &i);
    }

    for (int j = 0;j < pthread_count; j ++) {
        pthread_join(thread_id[j], NULL);
        printf("pthread [%d] returns\n", j);
    }

    if (NULL != thread_id) {
        free(thread_id);
    }

    kc_destroy();

    return 0;
}

static void *test_thread(void *arg)
{
    char key[128];
    char secret[128];
    int thi = *(int *)arg;
    uint8_t *out_buf = NULL;
    uint32_t out_len = 0;

    memset(key, 0, 128);
    memset(secret, 0, 128);
    sprintf(key, "sec_sst_test_same_uid_test_%04d_key", thi);
    sprintf(secret, "sec_sst_test_same_uid_test_%04d_secret", thi);

    printf("key: %s, secret: %s\n", key, secret);
    test_sec_sst(key, secret, &out_buf, &out_len);

    if (memcmp(secret, out_buf, out_len)) {
        printf("EEEEEEEEE the %dth thread test failed\n", thi);
    } else {
        printf("the %dth thread test success, secret %s\n", thi, out_buf);
    }

    if (out_buf) {
        free(out_buf);
        out_buf = NULL;
    }

    return NULL;
}

static void test_sec_sst(char *key, char *secret, uint8_t **out_buf, uint32_t *out_len)
{
    uint32_t secret_len = strlen(secret);
    kc_key_type_t key_type = 0;
    uint32_t ret = 0;

    if (kc_add_item(key, secret, secret_len, key_type) == 0) {
            ret = kc_get_item(key, *out_buf, out_len, &key_type);
            if (ret != KC_ERROR_SHORT_BUFFER) {
                printf("kc get item length failed\n");
                return;
            }

            *out_buf = (uint8_t *)malloc(*out_len + 1);
            if (*out_buf == NULL) {
                printf("malloc failed\n");
                return;
            }
            memset(*out_buf, 0, *out_len + 1);

            ret = kc_get_item(key, *out_buf, out_len, &key_type);
            if (ret != KC_SUCCESS) {
                printf("kc get item failed\n");
                free(*out_buf);
                *out_buf = NULL;
                return;
            }
            printf("test store and get success.\n");
    } else {
        printf("store item fail.\n");
    }
}

static void usage() {
    printf("Usage: sec_sst_test_performance [OPTION]... \n"
           "Security storage service's stress testing program.\n"
           "\n"
           "-p TREAD_NUM	start THREAD_NUM threads\n"
           "\n"
           "Examples:"
           "  sec_sst_test_performance -p 2	start two threads.\n");
}
