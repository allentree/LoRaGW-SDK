#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "km_test_comm.h"
#include "km_test_dbg.h"
#include "km.h"


#if CONFIG_RSA_SUPPORT

uint32_t test_sign_verify(char *name, uint32_t name_len)
{
    km_sign_param sign_params;
    uint8_t test_data[256];
    size_t test_data_len = 89;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    uint32_t ret = 0;

    memset(test_data, 44, test_data_len);

    sign_params.padding_type = KM_PKCS1;
    sign_params.digest_type = KM_SHA1;
    ret = km_sign(name, name_len, &sign_params, test_data,
               test_data_len, signature, &signature_len);
    if (ret != KM_ERR_SHORT_BUFFER) {
        KM_TEST_ERR("test sign short buffer failed 0x%x\n", ret);
        ret = KM_ERR_GENERIC;
        return ret;
    }

    signature = malloc(signature_len);
    if (!signature) {
        KM_TEST_ERR("malloc failed\n");
        return KM_ERR_OUT_OF_MEMORY;
    }

    ret = km_sign(name, name_len, &sign_params, test_data,
               test_data_len, signature, &signature_len);
    if (ret) {
        KM_TEST_ERR("sign failed 0x%x\n", ret);
        goto clean;
    }
#if KM_TEST_DEBUG
    km_test_dump_data("signature is :", signature, signature_len);
#endif
    KM_TEST_INF("sign success\n");

    ret = km_verify(name, name_len, &sign_params, test_data,
                 test_data_len, signature, signature_len);
    if (ret) {
        KM_TEST_ERR("verify failed 0x%x\n", ret);
        goto clean;
    }
    KM_TEST_INF("verify success\n");

clean:
    if (signature) {
        km_free(signature);
        signature = NULL;
    }

    return ret;
}

uint32_t test_encrypt_decrypt(char *name, uint32_t name_len)
{
    uint8_t test_data[256];
    size_t test_data_len = 100;
    km_enc_param enc_params;
    uint8_t *enc = NULL;
    size_t enc_len = 0;
    uint8_t *dec = NULL;
    size_t dec_len = 0;
    uint32_t ret = 0;

    memset(test_data, 33, test_data_len);
    enc_params.padding_type = KM_PKCS1;
    ret = km_asym_encrypt((const char *)name, name_len, &enc_params, test_data,
                  test_data_len, enc, &enc_len);
    if (ret != KM_ERR_SHORT_BUFFER) {
        KM_TEST_ERR("test rsa encrypt short buffer failed 0x%x\n", ret);
        ret = KM_ERR_GENERIC;
        return ret;
    }

    enc = malloc(enc_len);
    if (!enc) {
        KM_TEST_ERR("malloc failed\n");
        return KM_ERR_OUT_OF_MEMORY;
    }

    ret = km_asym_encrypt((const char *)name, name_len, &enc_params, test_data,
                  test_data_len, enc, &enc_len);
    if (ret) {
        KM_TEST_ERR("enc failed 0x%x\n", ret);
        goto clean;
    }

#if KM_TEST_DEBUG
    km_test_dump_data("enc is:", enc, enc_len);
#endif

    ret = km_asym_decrypt(name, name_len, &enc_params, enc, enc_len,
                 dec, &dec_len);
    if (ret != KM_ERR_SHORT_BUFFER) {
        KM_TEST_ERR("test rsa encrypt short buffer failed 0x%x\n", ret);
        ret = KM_ERR_GENERIC;
        goto clean;
    }

    dec = malloc(dec_len);
    if (!dec) {
        KM_TEST_ERR("malloc failed\n");
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }
    ret = km_asym_decrypt(name, name_len, &enc_params, enc, enc_len,
                 dec, &dec_len);
    if (ret) {
        KM_TEST_ERR("dec failed 0x%x\n", ret);
        goto clean;
    }

#if KM_TEST_DEBUG
    km_test_dump_data("dec result is:", dec, dec_len);
#endif

    if (memcmp(dec, test_data, test_data_len)) {
        KM_TEST_ERR("dec result is wrong\n");
        ret = -1;
        goto clean;
    }

    KM_TEST_INF("enc dec success\n");

clean:
    if (dec) {
        km_free(dec);
        dec = NULL;
    }
    if (enc) {
        km_free(enc);
        enc = NULL;
    }

    return ret;
}

uint32_t km_asym_test()
{
    uint32_t ret = 0;

    KM_TEST_INF("start test import\n");
    ret = test_import(RSA_IM_NAME, RSA_IM_NAME_LEN, KM_RSA);
    if (ret && ret != KM_ERR_ACCESS_CONFLICT) {
        KM_TEST_ERR("test import failed 0x%x\n", ret);
        return ret;
    }

    ret = test_sign_verify(RSA_IM_NAME, RSA_IM_NAME_LEN);
    if (ret) {
        KM_TEST_ERR("test import failed 0x%x\n", ret);
        return ret;
    }

    ret = test_encrypt_decrypt(RSA_IM_NAME, RSA_IM_NAME_LEN);
    if (ret) {
        KM_TEST_ERR("test import failed 0x%x\n", ret);
        return ret;
    }

    ret = test_delete(RSA_IM_NAME, RSA_IM_NAME_LEN);
    if (ret) {
        KM_TEST_ERR("test import failed 0x%x\n", ret);
        return ret;
    }

    return ret;
}

uint32_t km_rsa_perf_test(uint32_t test_count)
{
    uint32_t i = 0;
    uint32_t ret = 0;
    double total_time, av_time;
    struct timeval start_tv, end_tv;

    km_sign_param sign_params;
    uint8_t test_data[256];
    size_t test_data_len = 100;
    uint8_t signature[256];
    size_t signature_len = 256;

    KM_TEST_INF("******************rsa perf test start*******************\n");
    ret = test_import(RSA_IM_NAME, RSA_IM_NAME_LEN, KM_RSA);
    if (ret && ret != KM_ERR_ACCESS_CONFLICT) {
        KM_TEST_ERR("test import/generate failed 0x%x\n", ret);
        return ret;
    }

    memset(test_data, 33, test_data_len);

    sign_params.padding_type = KM_PKCS1;
    sign_params.digest_type = KM_SHA1;

    gettimeofday(&start_tv, NULL);
    for (i = 0; i < test_count; i++) {
        ret = km_sign(RSA_IM_NAME, RSA_IM_NAME_LEN, &sign_params, test_data,
               test_data_len, signature, &signature_len);
        if (ret) {
            KM_TEST_ERR("test enc dec failed 0x%x\n", ret);
            test_delete(RSA_IM_NAME, RSA_IM_NAME_LEN);
            return ret;
        }
    }
    gettimeofday(&end_tv, NULL);
    total_time = (end_tv.tv_usec - start_tv.tv_usec)/1000 +
                 (end_tv.tv_sec - start_tv.tv_sec) * 1000;

    av_time = total_time / test_count;
    KM_TEST_INF("rsa sign total time: %fms, av_time: %fms\n", total_time, av_time);

    gettimeofday(&start_tv, NULL);
    for (i = 0; i < test_count; i++) {
        ret = km_verify(RSA_IM_NAME, RSA_IM_NAME_LEN, &sign_params, test_data,
                 test_data_len, signature, signature_len);
        if (ret) {
            KM_TEST_ERR("test enc dec failed 0x%x\n", ret);
            test_delete(RSA_IM_NAME, RSA_IM_NAME_LEN);
            return ret;
        }
    }
    gettimeofday(&end_tv, NULL);
    total_time = (end_tv.tv_usec - start_tv.tv_usec)/1000 +
                 (end_tv.tv_sec - start_tv.tv_sec) * 1000;

    av_time = total_time / test_count;
    KM_TEST_INF("rsa verify total time: %fms, av_time: %fms\n", total_time, av_time);

    km_enc_param enc_params;
    enc_params.padding_type = KM_PKCS1;
    uint8_t enc[256];
    size_t enc_len = 256;
    uint8_t dec[256];
    size_t dec_len = 256;

    gettimeofday(&start_tv, NULL);
    for (i = 0; i < test_count; i++) {
        ret = km_asym_encrypt(RSA_IM_NAME, RSA_IM_NAME_LEN, &enc_params, test_data,
                  test_data_len, enc, &enc_len);
        if (ret) {
            KM_TEST_ERR("test enc dec failed 0x%x\n", ret);
            test_delete(RSA_IM_NAME, RSA_IM_NAME_LEN);
            return ret;
        }
    }
    gettimeofday(&end_tv, NULL);
    total_time = (end_tv.tv_usec - start_tv.tv_usec)/1000 +
                 (end_tv.tv_sec - start_tv.tv_sec) * 1000;

#if KM_TEST_DEBUG
    km_test_dump_data("enc is:", enc, enc_len);
#endif

    av_time = total_time / test_count;
    KM_TEST_INF("rsa enc total time: %fms, av_time: %fms\n", total_time, av_time);

    gettimeofday(&start_tv, NULL);
    for (i = 0; i < test_count; i++) {
        ret = km_asym_decrypt(RSA_IM_NAME, RSA_IM_NAME_LEN, &enc_params, enc, enc_len,
                 dec, &dec_len);
        if (ret) {
            KM_TEST_ERR("test enc dec failed 0x%x\n", ret);
            test_delete(RSA_IM_NAME, RSA_IM_NAME_LEN);
            return ret;
        }
    }

    gettimeofday(&end_tv, NULL);
    total_time = (end_tv.tv_usec - start_tv.tv_usec)/1000 +
                 (end_tv.tv_sec - start_tv.tv_sec) * 1000;

    av_time = total_time / test_count;
    KM_TEST_INF("rsa dec total time: %fms, av_time: %fms\n", total_time, av_time);

    ret = test_delete(RSA_IM_NAME, RSA_IM_NAME_LEN);
    if (ret) {
        KM_TEST_ERR("EEEEE test_delete failed\n");
        return ret;
    }

    return ret;
}

#endif /* CONFIG_RSA_SUPPORT */


