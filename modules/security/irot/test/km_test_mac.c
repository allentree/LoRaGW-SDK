#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include "km_test_comm.h"
#include "km_test_dbg.h"
#include "km.h"

static uint8_t hmac_test_data[141] = {
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01,
   0x02, 0x03, 0x04, 0x05, 0x13
};
uint32_t hmac_test_len = 141;

static uint8_t hmac_md5[16] = {
    0x20, 0xc5, 0xc6, 0xa7, 0x17, 0x6f, 0x27, 0xfe, 0x7a, 0x1d,
    0x7e, 0x85, 0x5b, 0x5c, 0xa8, 0xc4
};
static uint8_t hmac_sha1[20] = {
    0xe5, 0xdf, 0x48, 0xfe, 0x08, 0x91, 0x37, 0xa2, 0x55, 0x95,
    0xbc, 0xf3, 0x76, 0x06, 0x92, 0x1e, 0x54, 0x98, 0xe0, 0x4b
};
static uint8_t hmac_sha256[32] = {
    0xd5, 0xce, 0x2b, 0x95, 0xa3, 0xea, 0x70, 0x69, 0x6a, 0x29,
    0xbf, 0xe7, 0x9b, 0xa2, 0xc9, 0x18, 0x27, 0x4d, 0x3f, 0xd7,
    0xae, 0xe7, 0x81, 0x88, 0x2a, 0xe7, 0x19, 0x68, 0x47, 0x07,
    0xa3, 0xb3
};


static uint32_t _km_mac_test(char *name, uint32_t name_len, km_digest_type hash_type)
{
    uint32_t ret = 0;
    km_sym_param sym_param;
    uint8_t dest[100];
    uint32_t dest_len = 100;

    memset(&sym_param, 0, sizeof(sym_param));
    sym_param.key_type = KM_HMAC;

    //for md5
    sym_param.hmac_param.hash_type = KM_MD5;
    ret = km_mac(name, name_len, &sym_param, NULL, 0,
            hmac_test_data, hmac_test_len, dest, &dest_len);
    if (ret) {
        KM_TEST_ERR("km mac failed 0x%x\n", ret);
    }

    return ret;
}

uint32_t km_mac_test()
{
    uint32_t ret = 0;
    km_sym_param sym_param;
    uint8_t dest[100];
    uint32_t dest_len = 100;

    ret = test_import(HMAC_IM_NAME, HMAC_IM_NAME_LEN, KM_HMAC);
    if (ret && ret != KM_ERR_ACCESS_CONFLICT) {
        KM_TEST_ERR("test import/generate failed 0x%x\n", ret);
        return ret;
    }

    memset(&sym_param, 0, sizeof(sym_param));
    sym_param.key_type = KM_HMAC;

    //for md5
    sym_param.hmac_param.hash_type = KM_MD5;
    ret = km_mac(HMAC_IM_NAME, HMAC_IM_NAME_LEN, &sym_param,
            NULL, 0, hmac_test_data, hmac_test_len, dest, &dest_len);
    if (ret || memcmp(dest, hmac_md5, dest_len)) {
        KM_TEST_ERR("km mac failed 0x%x\n", ret);
        goto clean;
    }
    KM_TEST_INF("*************hmac test md5 success******************\n");

    //for sha1
    sym_param.hmac_param.hash_type = KM_SHA1;
    ret = km_mac(HMAC_IM_NAME, HMAC_IM_NAME_LEN, &sym_param,
            NULL, 0, hmac_test_data, hmac_test_len, dest, &dest_len);
    if (ret || memcmp(dest, hmac_sha1, dest_len)) {
        KM_TEST_ERR("km mac failed 0x%x\n", ret);
        goto clean;
    }
    KM_TEST_INF("*************hmac test sha1 success******************\n");

    //for sha256
    sym_param.hmac_param.hash_type = KM_SHA256;
    ret = km_mac(HMAC_IM_NAME, HMAC_IM_NAME_LEN, &sym_param,
            NULL, 0, hmac_test_data, hmac_test_len, dest, &dest_len);
    if (ret || memcmp(dest, hmac_sha256, dest_len)) {
        KM_TEST_ERR("km mac failed 0x%x\n", ret);
        goto clean;
    }
    KM_TEST_INF("*************hmac test sha256 success******************\n");

clean:
    if (test_delete(HMAC_IM_NAME, HMAC_IM_NAME_LEN)) {
        KM_TEST_ERR("test delete hmac key failed\n");
    }

    return ret;
}

uint32_t km_mac_short_buffer_test()
{
    uint32_t ret = 0;
    km_sym_param sym_param;
    uint8_t *dest = NULL;
    uint32_t dest_len = 0;

    ret = test_import(HMAC_IM_NAME, HMAC_IM_NAME_LEN, KM_HMAC);
    if (ret && ret != KM_ERR_ACCESS_CONFLICT) {
        KM_TEST_ERR("test import/generate failed 0x%x\n", ret);
        return ret;
    }

    memset(&sym_param, 0, sizeof(sym_param));
    sym_param.key_type = KM_HMAC;

    //for md5
    sym_param.hmac_param.hash_type = KM_MD5;
    ret = km_mac(HMAC_IM_NAME, HMAC_IM_NAME_LEN, &sym_param,
            NULL, 0, hmac_test_data, hmac_test_len, dest, &dest_len);
    if (ret != KM_ERR_SHORT_BUFFER) {
        KM_TEST_ERR("km mac get len failed\n");
        goto clean;
    }
    dest = malloc(dest_len);
    if (!dest) {
        KM_TEST_ERR("malloc failed\n");
        goto clean;
    }

    ret = km_mac(HMAC_IM_NAME, HMAC_IM_NAME_LEN, &sym_param,
            NULL, 0, hmac_test_data, hmac_test_len, dest, &dest_len);
    if (ret || memcmp(dest, hmac_md5, dest_len)) {
        KM_TEST_ERR("wrong md5 hmac\n");
        ret = KM_ERR_GENERIC;
        if (dest) {
            free(dest);
            dest = NULL;
        }
        goto clean;
    }
    KM_TEST_INF("*************hmac test short buffer md5 success******************\n");

    //for sha1
    sym_param.hmac_param.hash_type = KM_SHA1;
    //dest for md5 is short for sha1
    ret = km_mac(HMAC_IM_NAME, HMAC_IM_NAME_LEN, &sym_param,
            NULL, 0, hmac_test_data, hmac_test_len, dest, &dest_len);
    if (ret != KM_ERR_SHORT_BUFFER) {
        KM_TEST_ERR("km mac get len failed\n");
        if (dest) {
            free(dest);
            dest = NULL;
        }
        goto clean;
    }
    if (dest) {
        free(dest);
        dest = NULL;
    }
    dest = (uint8_t *)malloc(dest_len);
    if (!dest) {
        KM_TEST_ERR("malloc failed\n");
        goto clean;
    }

    ret = km_mac(HMAC_IM_NAME, HMAC_IM_NAME_LEN, &sym_param,
            NULL, 0, hmac_test_data, hmac_test_len, dest, &dest_len);
    if (ret || memcmp(dest, hmac_sha1, dest_len)) {
        KM_TEST_ERR("wrong md5 hmac\n");
        ret = KM_ERR_GENERIC;
        if (dest) {
            free(dest);
            dest = NULL;
        }
        goto clean;
    }
    if (dest) {
        free(dest);
        dest = NULL;
    }
    KM_TEST_INF("*************hmac test short buffer sha1 success****************\n");

    //for sha256
    sym_param.hmac_param.hash_type = KM_SHA256;
    dest_len = 0;
    ret = km_mac(HMAC_IM_NAME, HMAC_IM_NAME_LEN, &sym_param,
            NULL, 0, hmac_test_data, hmac_test_len, dest, &dest_len);
    if (ret != KM_ERR_SHORT_BUFFER) {
        KM_TEST_ERR("km mac get len failed\n");
        goto clean;
    }
    dest = (uint8_t *)malloc(dest_len);
    if (!dest) {
        KM_TEST_ERR("malloc failed\n");
        goto clean;
    }

    ret = km_mac(HMAC_IM_NAME, HMAC_IM_NAME_LEN, &sym_param,
            NULL, 0, hmac_test_data, hmac_test_len, dest, &dest_len);
    if (ret || memcmp(dest, hmac_sha256, dest_len)) {
        KM_TEST_ERR("wrong md5 hmac\n");
        ret = KM_ERR_GENERIC;
        if (dest) {
            free(dest);
            dest = NULL;
        }
        goto clean;
    }
    if (dest) {
        free(dest);
        dest = NULL;
    }
    KM_TEST_INF("*************hmac test short buffer sha256 success*************\n");

clean:
    if (test_delete(HMAC_IM_NAME, HMAC_IM_NAME_LEN)) {
        KM_TEST_ERR("test delete hmac key failed\n");
    }

    return ret;
}

uint32_t km_mac_whole_test()
{
    int ret = 0;

    ret = km_mac_test();
    if (ret) {
        KM_TEST_ERR("km mac test failed\n");
        return ret;
    }
    KM_TEST_INF("\n<<<<<< ks mac test success ! >>>>>>>>\n");

    ret = km_mac_short_buffer_test();
    if (ret) {
        KM_TEST_ERR("km mac test failed\n");
        return ret;
    }
    KM_TEST_INF("\n<<<<<< ks mac short buffer test success ! >>>>>>>>\n");

    return ret;
}

int km_mac_perf_test(uint32_t test_count)
{
    uint32_t i = 0;
    uint32_t ret = 0;
    double total_time, av_time;
    struct timeval start_tv, end_tv;

    KM_TEST_INF("******************hmac perf test start*******************\n");
    ret = test_generate(HMAC_GEN_NAME, HMAC_GEN_NAME_LEN, KM_HMAC, 128);
    if (ret && ret != KM_ERR_ACCESS_CONFLICT) {
        KM_TEST_ERR("test import/generate failed 0x%x\n", ret);
        return ret;
    }

    gettimeofday(&start_tv, NULL);
    for (i = 0; i < test_count; i++) {
        ret = _km_mac_test(HMAC_GEN_NAME, HMAC_GEN_NAME_LEN, KM_SHA1);
        if (ret) {
            KM_TEST_ERR("km mac test failed 0x%x\n", ret);
            test_delete(HMAC_GEN_NAME, HMAC_GEN_NAME_LEN);
            return ret;
        }
    }

    gettimeofday(&end_tv, NULL);
    total_time = (end_tv.tv_usec - start_tv.tv_usec)/1000 +
                 (end_tv.tv_sec - start_tv.tv_sec) * 1000;

    av_time = total_time / test_count;
    KM_TEST_INF("hmac total time: %fms, av_time: %fms\n", total_time, av_time);
    ret = test_delete(HMAC_GEN_NAME, HMAC_GEN_NAME_LEN);
    if (ret) {
        KM_TEST_ERR("EEEEE test_delete failed\n");
        return ret;
    }

    return ret;
}

