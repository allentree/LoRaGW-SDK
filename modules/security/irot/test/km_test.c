/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>

#include "km_test_comm.h"
#include "km_test_dbg.h"
#include "km_test_mac.h"
#include "km_test_rsa.h"
#include "km_test_aes.h"
#include "km_test_envelope.h"
#include "km_test_id.h"

#include "irot.h"

#define THREAD_NUM 0x4

#ifdef LINUX_TEST_BIN
static uint32_t thread_id = 0;
#endif

uint32_t perf_test(void)
{
    uint32_t test_count = 1000;

    KM_TEST_INF("******************perf test start*******************\n");
#if CONFIG_AES_SUPPORT
    km_cipher_perf_test(test_count);
#endif /* CONFIG_AES_SUPPORT */

#if CONFIG_HMAC_SUPPORT
    km_mac_perf_test(test_count);
#endif /* CONFIG_HMAC_TEST */

#if CONFIG_RSA_SUPPORT
    km_rsa_perf_test(test_count);
#endif /* CONFIG_RSA_SUPPORT */

#if CONFIG_ENVELOPE_SUPPORT
    km_envelope_perf_test(test_count);
#endif /* CONFIG_ENVELOPE_SUPPORT */

    return 0;
}

void stress_test(void)
{
 //   uint32_t test_count = 100;
    uint32_t i = 0;
    int ret = 0;

    KM_TEST_INF("******************stress test start*******************\n");
    for (i = 0; ; i++) {
#if CONFIG_RSA_SUPPORT
        ret = test_import(RSA_IM_NAME, RSA_IM_NAME_LEN, KM_RSA);
        if (ret && ret != KM_ERR_ACCESS_CONFLICT) {
            KM_TEST_ERR("EEEEE test_import %d times failed\n", i);
            return;
        }

        //sleep(1);

        ret = test_sign_verify(RSA_IM_NAME, RSA_IM_NAME_LEN);
        if (ret) {
            KM_TEST_ERR("EEEEE test_sign_verify %d times failed\n", i);
            test_delete(RSA_IM_NAME, RSA_IM_NAME_LEN);

            return;
        }

        //sleep(1);
        ret = test_encrypt_decrypt(RSA_IM_NAME, RSA_IM_NAME_LEN);
        if (ret) {
            KM_TEST_ERR("EEEEEE test_enc_dec %d times failed\n", i);
            test_delete(RSA_IM_NAME, RSA_IM_NAME_LEN);
            return;
        }

        //sleep(1);
        ret = test_delete(RSA_IM_NAME, RSA_IM_NAME_LEN);
        if (ret) {
            KM_TEST_ERR("EEEEE test_delete %d times failed\n", i);
            return;
        }
#endif /* CONFIG_RSA_SUPPORT */
#if CONFIG_AES_SUPPORT
        ret = km_cipher_whole_test(AES_IM_NAME, AES_IM_NAME_LEN);
        if (ret) {
            KM_TEST_ERR("EEEEE test_sym whole test %d times failed\n", i);
            return;
        }
        //sleep(1);
#endif /* CONFIG_AES_SUPPORT */
#if CONFIG_HMAC_SUPPORT
        ret = km_mac_whole_test();
        if (ret) {
            KM_TEST_ERR("EEEEE test mac test %d times failed\n", i);
            return;
        }
#endif /* CONFIG_HMAC_TEST */

#if CONFIG_ENVELOPE_SUPPORT
        ret = km_envelope_whole_test();
        if (ret) {
            KM_TEST_ERR("EEEEE test envelope test %d times failed\n", i);
            return;
        }
#endif /* CONFIG_ENVELOPE_TEST */

        KM_TEST_INF("********** test %d times success*****\n", i);
    }

    return;
}

#ifdef LINUX_TEST_BIN
void * thread_content(void* argv)
{
    char name[8] = {'k', 'm', 'T', 'e', 's', 't'};
    uint32_t test_count = 10;
    uint32_t i = 0;
    int ret = 0;

    thread_id++;
    name[6] = thread_id + '0';
    name[7] = '\0';

    KM_TEST_INF("******************name is %s start*******************\n", name);
    for (i = 0; i < test_count; i++) {
#if CONFIG_RSA_SUPPORT
        ret = test_import(name, 7, KM_RSA);
        if (ret) {
            KM_TEST_ERR("EEEEE %s test_import %d times failed\n", name, i);
            return NULL;
        }

        sleep(1);

        ret = test_sign_verify(name, 7);
        if (ret) {
            KM_TEST_ERR("EEEEE %s test_sign_verify %d times failed\n", name, i);
            goto clean;
        }

        sleep(1);
        ret = test_encrypt_decrypt(name, 7);
        if (ret) {
            KM_TEST_ERR("EEEEEE %s test_enc_dec %d times failed\n", name, i);
            goto clean;
        }

        sleep(1);

        ret = test_delete(name, 7);
        if (ret) {
            KM_TEST_ERR("EEEEE  %s test_delete %d times failed\n", name, i);
            return NULL;
        }
#endif /* CONFIG_RSA_SUPPORT */
#if CONFIG_AES_SUPPORT
        ret = test_import(name, 7, KM_AES);
        if (ret) {
            KM_TEST_ERR("EEEEE %s test_import %d times failed\n", name, i);
            return NULL;
        }

        ret = test_cipher_enc_dec(name, 7, KM_CBC, KM_NO_PADDING);
        if (ret) {
            KM_TEST_ERR("EEEEE %s cipher  test %d times failed\n", name, i);
            goto clean;
        }

        ret = test_delete(name, 7);
        if (ret) {
            KM_TEST_ERR("EEEEE  %s test_delete %d times failed\n", name, i);
            return NULL;
        }
        KM_TEST_INF("*********name is %s test %d times success****************\n", name, i);
#endif /* CONFIG_AES_SUPPORT */
    }

    KM_TEST_INF("*********multi thread test success********\n");
    return NULL;

clean:
    ret = test_delete(name, 7);
    if (ret) {
        KM_TEST_ERR("EEEEE  %s test_delete %d times failed\n", name, i);
            return NULL;
    }

    KM_TEST_ERR("EEEEE  %s %d times failed\n", name, i);
    return NULL;
}

static void thread_test()
{
    uint8_t i = 0;
    pthread_t thread[THREAD_NUM];

    for(i = 0; i < THREAD_NUM; i++) {
        pthread_create(&thread[i], NULL, thread_content, NULL);
    }

    for(i = 0; i < THREAD_NUM; i++){
        pthread_join(thread[i],NULL);
    }

    return;
}

static void printf_help()
{
    printf("Usage:              prov_test [option]\n");
    printf("-h:                 display helpful information.\n");
    printf("generate key_type:  test generate key\n");
    printf("import key_type:    test import key\n");
    printf("delete key_type:    test delete key\n");
    printf("enc_dec:            test rsa encrypt decrypt\n");
    printf("sig_ver:            test rsa sign verify\n");
    printf("cipher:             test aes encrypt decrypt\n");
    printf("hmac:               test hmac\n");
    printf("stress_test:        stress test\n");
    printf("multi_thread:       multi thread test\n");
    printf("perf_test:          test performance\n");
    printf("get_id2:            test get id2\n");
    printf("set_get_id2:        test set and get id2\n");
    printf("attestation:        test get attestation\n");
    printf("envelope:           test envelope\n");

    return;
}

int main(int argc, char *argv[])
{
    uint32_t ret = 0;
    int res = 0;

    if ((argc < 2) || (0 == strcmp(argv[1], "-h"))) {
        printf_help();
        return -1;
    }

    irot_init();
    ret = km_init();
    if (ret) {
        KM_TEST_ERR("km init failed\n");
        goto out;
    }

    if (!strcmp(argv[1], "generate")) { //get the whole prov data
#if CONFIG_RSA_SUPPORT
        if (!strcmp(argv[2], "rsa")) {
            ret = test_generate(RSA_GEN_NAME, RSA_GEN_NAME_LEN, KM_RSA, 1024);
            goto out;
        }
#endif
#if CONFIG_AES_SUPPORT
        if (!strcmp(argv[2], "aes")) {
            ret = test_generate(AES_GEN_NAME, AES_GEN_NAME_LEN, KM_AES, 128);
            goto out;
        }
#endif
#if CONFIG_HMAC_SUPPORT
        if (!strcmp(argv[2], "hmac")) {
            ret = test_generate(HMAC_GEN_NAME, HMAC_GEN_NAME_LEN, KM_HMAC, 128);
            goto out;
        }
#endif
        KM_TEST_ERR("wrong key type %s\n", argv[2]);
    } else if (!strcmp(argv[1], "import")) { //write prov
#if CONFIG_RSA_SUPPORT
        if (!strcmp(argv[2], "rsa")) {
            ret = test_import(RSA_IM_NAME, RSA_IM_NAME_LEN, KM_RSA);
            goto out;
        }
#endif
#if CONFIG_AES_SUPPORT
        if (!strcmp(argv[2], "aes")) {
            ret = test_import(AES_IM_NAME, AES_IM_NAME_LEN, KM_AES);
            goto out;
        }
#endif
#if CONFIG_HMAC_SUPPORT
        if (!strcmp(argv[2], "hmac")) {
            ret = test_import(HMAC_IM_NAME, HMAC_IM_NAME_LEN, KM_HMAC);
            goto out;
        }
#endif
        KM_TEST_ERR("wrong key type %s\n", argv[2]);

    } else if (!strcmp(argv[1], "export")) {
        //ret = test_export(NAME, NAME_LEN);
    } else if (!strcmp(argv[1], "delete")) {
#if CONFIG_RSA_SUPPORT
        if (!strcmp(argv[2], "rsa")) {
            ret = test_delete(RSA_IM_NAME, RSA_IM_NAME_LEN);
            goto out;
        }
#endif
#if CONFIG_AES_SUPPORT
        if (!strcmp(argv[2], "aes")) {
            ret = test_delete(AES_IM_NAME, AES_IM_NAME_LEN);
            goto out;
        }
#endif
#if CONFIG_HMAC_SUPPORT
        if (!strcmp(argv[2], "hmac")) {
            ret = test_delete(HMAC_IM_NAME, HMAC_IM_NAME_LEN);
            goto out;
        }
#endif
    }
#if CONFIG_RSA_SUPPORT
    else if (!strcmp(argv[1], "enc_dec")) {
        ret = test_encrypt_decrypt(RSA_IM_NAME, RSA_IM_NAME_LEN);
    } else if (!strcmp(argv[1], "sig_ver")) {
        ret = test_sign_verify(RSA_IM_NAME, RSA_IM_NAME_LEN);
    }
#endif
#if CONFIG_AES_SUPPORT
    else if (!strcmp(argv[1], "cipher")) {
        ret = km_cipher_whole_test(AES_IM_NAME, AES_IM_NAME_LEN);
    }
#endif
#if CONFIG_HMAC_SUPPORT
    else if (!strcmp(argv[1], "hmac")) {
        ret = km_mac_whole_test();
    }
#endif
    else if (!strcmp(argv[1], "multi_thread")) {
        thread_test();
    } else if (!strcmp(argv[1], "stress_test")) {
        stress_test();
    } else if (!strcmp(argv[1], "perf_test")) {
        ret = perf_test();
    } else if (!strcmp(argv[1], "get_id2")) {
        ret = test_get_id2();
    } else if (!strcmp(argv[1], "set_get_id2")) {
        ret = test_set_get_id2();
    } else if (!strcmp(argv[1], "attestation")) {
        ret = km_get_attestation_test();
#if CONFIG_ENVELOPE_SUPPORT
    } else if (!strcmp(argv[1], "envelope")) {
        ret = km_envelope_whole_test();
#endif
    } else {
        ret = KM_ERR_GENERIC;
    }

out:
    if (ret) {
        KM_TEST_ERR("%s failed\n", argv[1]);
        res = -1;
    } else {
        KM_TEST_INF("%s success\n", argv[1]);
    }

    irot_destroy();
    return res;
}
#endif /* LINUX_TEST_BIN */
