#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include "km_test_comm.h"
#include "km_test_dbg.h"
#include "km.h"

#define UPDATE_TEST_LEN 48
#define ENC_DEC_TEST_LEN 52
#define PERF_LEN 1024 //1K

static uint8_t aes_test_data[] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
};

static uint8_t usr_iv[16] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
};

typedef struct _update_short_t {
    uint32_t update1;
    uint32_t update2;
} update_short_t;

static uint32_t short_buf_test_count = 5;
static uint32_t short_buf_test[] = { 13, 17, 33, 16, 32 };
static uint32_t update_short_count = 8;
static update_short_t update_short[] = { {1, 14}, {1, 15}, {1, 17}, {3, 32},
                      {16, 15}, {16, 31}, {32, 15}, {33, 15}};

static uint32_t test_envelope_enc_dec(char *name, uint32_t name_len)
{
    uint32_t test_len = ENC_DEC_TEST_LEN;
    km_op_handle_t op_handle = NULL;
    uint8_t src[ENC_DEC_TEST_LEN];
    uint8_t enc_array[ENC_DEC_TEST_LEN] = {0};
    uint8_t dec_array[ENC_DEC_TEST_LEN] = {0};
    uint32_t src_len = test_len;
    uint32_t dest_len = test_len;
    uint32_t enc_len = 0;
    uint32_t dec_len = 0;
    uint8_t *enc = enc_array;
    uint8_t *dec = dec_array;
    uint8_t *iv = NULL;
    uint8_t iv_len = 0;
    uint32_t ret = 0;
    uint8_t protected_key[16];
    uint32_t protected_key_len = 16;
    km_purpose_type is_enc = 0;

    km_memcpy(src, aes_test_data, test_len);

    iv = usr_iv;
    iv_len = 16;

    is_enc = KM_PURPOSE_ENCRYPT;
    ret = km_envelope_begin(&op_handle, name, name_len, iv, iv_len,
            protected_key, &protected_key_len, is_enc);
    if (ret) {
        KM_TEST_ERR("begin failed 0x%x\n", ret);
        goto clean;
    }
    ret = km_envelope_update(op_handle, src, src_len, enc, &dest_len);
    if (ret) {
        KM_TEST_ERR("test enc_dec update failed 0x%x\n", ret);
        goto clean;
    }
    enc_len += dest_len;
    dest_len = ENC_DEC_TEST_LEN;
    ret = km_envelope_finish(op_handle, NULL, 0, enc + enc_len, &dest_len);
    if (ret) {
        KM_TEST_ERR("test enc_dec finish failed 0x%x\n", ret);
        return ret;
    }
    enc_len += dest_len;
#if KM_TEST_DEBUG
    //km_test_dump_data("cipher enc dest :", enc, enc_len);
#endif

    dest_len = ENC_DEC_TEST_LEN;
    op_handle = NULL;
    is_enc = KM_PURPOSE_DECRYPT;
    ret = km_envelope_begin(&op_handle, name, name_len,
            iv, iv_len, protected_key, &protected_key_len, is_enc);
    if (ret) {
        KM_TEST_ERR("test dec begin failed 0x%x\n", ret);
        goto clean;
    }
    ret = km_envelope_update(op_handle, enc, enc_len, dec, &dest_len);
    if (ret) {
        KM_TEST_ERR("test dec update failed 0x%x\n", ret);
        goto clean;
    }
    dec_len += dest_len;
    dest_len = ENC_DEC_TEST_LEN;
    ret = km_envelope_finish(op_handle, NULL, 0, dec + dec_len, &dest_len);
    if (ret) {
        KM_TEST_ERR("test dec finish failed 0x%x\n", ret);
        return ret;
    }

    dec_len += dest_len;

#if KM_TEST_DEBUG
    km_test_dump_data("cipher dec dest :", dec, dec_len);
#endif

    if(dec_len != test_len || memcmp(dec, src, test_len)) {
        KM_TEST_ERR("dec result is not correct\n");
#if KM_TEST_DEBUG
        km_test_dump_data("envelope src is :", src, src_len);
        km_test_dump_data("envelope dec is :", dec, test_len);
#endif
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;

clean:
    if (km_envelope_finish(op_handle, NULL, 0, NULL, NULL)) {
        KM_TEST_ERR("test enc dec finish failed\n");
    }

    return ret;
}

// three times update
uint32_t test_update(char *name, uint32_t name_len)
{
    uint32_t test_len = 0;
    uint32_t dest_len = 256;
    uint8_t enc_array[256];
    uint8_t *enc = enc_array;
    uint32_t enc_len = 0;
    uint8_t src_array[256];
    uint8_t *src = src_array;
    uint8_t dec_array[256];
    uint8_t *dec = dec_array;
    uint32_t dec_len = 0;
    km_op_handle_t op_handle = NULL;
    uint32_t ret = 0;
    uint8_t *iv = usr_iv;
    uint32_t iv_len = 16;
    uint32_t enc1_len = 1;
    uint32_t enc2_len = 46 - 1;
    uint32_t enc3_len = 1;
    uint32_t encl_len = 0;

    uint32_t dec1_len = 1;
    uint32_t dec2_len = 16;
    uint32_t dec3_len = 30;
    uint32_t decl_len = 0;
    km_purpose_type is_enc = 0;
    uint8_t protected_key[48];
    uint32_t protected_key_len = 48;

    test_len = UPDATE_TEST_LEN;
    encl_len = test_len - (enc1_len + enc2_len + enc3_len);

    is_enc = KM_PURPOSE_ENCRYPT;

    km_memcpy(src, aes_test_data, test_len);

    ret = km_envelope_begin(&op_handle, name, name_len, iv, iv_len,
            protected_key, &protected_key_len, is_enc);

    if (ret || protected_key_len != 16) {
        KM_TEST_ERR("begin failed 0x%x\n", ret);
        goto clean;
    }
    ret = km_envelope_update(op_handle, src, enc1_len, enc, &dest_len);
    if (ret) {
        KM_TEST_ERR("update 1 failed 0x%x\n", ret);
        goto clean;
    }
    enc_len += dest_len;
    src += enc1_len;
    dest_len = 256;
    ret = km_envelope_update(op_handle, src, enc2_len, enc + enc_len, &dest_len);
    if (ret) {
        KM_TEST_ERR("enc update 2 failed 0x%x\n", ret);
        goto clean;
    }
    enc_len += dest_len;
    src += enc2_len;
    dest_len = 256;

    ret = km_envelope_update(op_handle, src, enc3_len, enc + enc_len, &dest_len);
    if (ret) {
        KM_TEST_ERR("enc update3 failed 0x%x\n", ret);
        goto clean;
    }
    enc_len += dest_len;
    src += enc3_len;
    dest_len = 256;
    ret = km_envelope_finish(op_handle, src, encl_len, enc + enc_len, &dest_len);
    if (ret) {
        KM_TEST_ERR("enc finish failed 0x%x\n", ret);
        return ret;;
    }
    enc_len += dest_len;

#if KM_TEST_DEBUG
    km_test_dump_data("enc dest is :", enc, enc_len);
#endif

    is_enc = KM_PURPOSE_DECRYPT;
    dest_len = 256;
    ret = km_envelope_begin(&op_handle, name, name_len, iv, iv_len,
            protected_key, &protected_key_len, is_enc);

    if (ret) {
        KM_TEST_ERR("begin failed 0x%x\n", ret);
        goto clean;
    }
    ret = km_envelope_update(op_handle, enc, dec1_len, dec, &dest_len);
    if (ret) {
        KM_TEST_ERR("dec update 1 failed 0x%x\n", ret);
        goto clean;
    }
    dec_len += dest_len;
    enc += dec1_len;
    dest_len = 256;

    ret = km_envelope_update(op_handle, enc, dec2_len, dec + dec_len, &dest_len);
    if (ret) {
        KM_TEST_ERR("dec update 2 failed 0x%x\n", ret);
        goto clean;
    }

    dec_len += dest_len;
    enc += dec2_len;
    dest_len = 256;

    ret = km_envelope_update(op_handle, enc, dec3_len, dec + dec_len, &dest_len);
    if (ret) {
        KM_TEST_ERR("dec update3 fialed 0x%x\n", ret);
        goto clean;
    }
    dec_len += dest_len;
    enc += dec3_len;
    dest_len = 256;

    decl_len = enc_len - (dec1_len + dec2_len + dec3_len);
    ret = km_envelope_finish(op_handle, enc, decl_len, dec + dec_len, &dest_len);
    if (ret) {
        KM_TEST_ERR("dec finish failed 0x%x\n", ret);
        return ret;
    }

    dec_len += dest_len;

#if KM_TEST_DEBUG
    km_test_dump_data("dec dest is :", dec, dec_len);
#endif

    if (memcmp(dec, src_array, test_len)) {
        KM_TEST_ERR("dec result is not correct\n");
        return KM_ERR_GENERIC;
    }

    return 0;

clean:
    if (km_envelope_finish(op_handle, NULL, 0, NULL, NULL)) {
        KM_TEST_ERR("finish failed\n");
    }

    return ret;
}

//test finish short buffer
static uint32_t test_envelope_short(char *name, uint32_t name_len,
                        uint32_t index)
{
    uint32_t test_len = short_buf_test[index];
    km_op_handle_t op_handle = NULL;
    uint8_t src[ENC_DEC_TEST_LEN];
    uint8_t enc_array[ENC_DEC_TEST_LEN];
    uint8_t dec_array[ENC_DEC_TEST_LEN];
    uint32_t dest_len = test_len;
    uint32_t enc_len = 0;
    uint32_t dec_len = 0;
    uint8_t *enc = enc_array;
    uint8_t *dec = dec_array;
    uint8_t *iv = NULL;
    uint8_t iv_len = 0;
    uint32_t ret = 0;
    uint32_t update_len = 3;
    uint32_t get_len = 0;
    uint8_t protected_key[16];
    uint32_t protected_key_len = 0;
    km_purpose_type is_enc = 0;

    km_memcpy(src, aes_test_data, test_len);

    iv = usr_iv;
    iv_len = 16;

    //to get buffer len
    is_enc = KM_PURPOSE_ENCRYPT;
    ret = km_envelope_begin(&op_handle, name, name_len, iv, iv_len,
            protected_key, &protected_key_len, is_enc);
    if (ret != KM_ERR_SHORT_BUFFER || protected_key_len != 16) {
        KM_TEST_ERR("get protected len failed 0x%x\n", ret);
        goto clean;
    }
    ret = km_envelope_begin(&op_handle, name, name_len, iv, iv_len,
            protected_key, &protected_key_len, is_enc);
    if (ret) {
        KM_TEST_ERR("begin failed 0x%x\n", ret);
        goto clean;
    }

    dest_len = test_len;
    ret = km_envelope_update(op_handle, src, update_len, enc, &dest_len);
    if (ret) {
        KM_TEST_ERR("test enc_dec update failed 0x%x\n", ret);
        goto clean;
    }
    enc_len += dest_len;
    dest_len = 0;
    ret = km_envelope_finish(op_handle, src + update_len,
            test_len - update_len, enc + enc_len, &dest_len);
    if (ret != KM_ERR_SHORT_BUFFER) {
        KM_TEST_ERR("test enc_dec finish get dest len failed ret %d\n", ret);
        ret = KM_ERR_GENERIC;
        return ret;
    }
    enc_len += dest_len;
    get_len = enc_len;
    //to get enc data
    enc_len = 0;
    ret = km_envelope_begin(&op_handle, name, name_len, iv, iv_len,
            protected_key, &protected_key_len, is_enc);
    if (ret) {
        KM_TEST_ERR("begin failed 0x%x\n", ret);
        goto clean;
    }
    dest_len = test_len;
    ret = km_envelope_update(op_handle, src, update_len, enc, &dest_len);
    if (ret) {
        KM_TEST_ERR("test enc_dec update failed 0x%x\n", ret);
        goto clean;
    }
    enc_len += dest_len;
    dest_len = get_len - enc_len;
    ret = km_envelope_finish(op_handle, src + update_len, test_len - update_len,
                enc + enc_len, &dest_len);
    if (ret) {
        KM_TEST_ERR("test enc_dec finish failed 0x%x\n", ret);
        return ret;
    }

    enc_len += dest_len;
#if KM_TEST_DEBUG
    km_test_dump_data("cipher enc dest :", enc, enc_len);
#endif /* KS_TEST_DEBUG */

   //dec get len
    dest_len = test_len;
    op_handle = NULL;
    is_enc = KM_PURPOSE_DECRYPT;

    ret = km_envelope_begin(&op_handle, name, name_len, iv, iv_len,
            protected_key, &protected_key_len, is_enc);
    if (ret) {
        KM_TEST_ERR("test dec begin failed 0x%x\n", ret);
        goto clean;
    }
    ret = km_envelope_update(op_handle, enc, update_len, dec, &dest_len);
    if (ret) {
        KM_TEST_ERR("test dec update failed 0x%x\n", ret);
        goto clean;
    }
    dec_len += dest_len;
    dest_len = 0; //for test short buffer
    ret = km_envelope_finish(op_handle, enc + update_len, enc_len - update_len, dec + dec_len, &dest_len);
    if (ret != KM_ERR_SHORT_BUFFER) {
        KM_TEST_ERR("test dec finish failed 0x%x\n", ret);
        ret = KM_ERR_GENERIC;
        return ret;
    }

    dec_len += dest_len;
    get_len = dec_len;
//    KM_TEST_INF("SHORT BUFFER: get dec len is %ld\n", (unsigned long)get_len);
    //dec get dec data
    dest_len = test_len;
    dec_len = 0;

    ret = km_envelope_begin(&op_handle, name, name_len, iv, iv_len,
            protected_key, &protected_key_len, is_enc);
    if (ret) {
        KM_TEST_ERR("test dec begin failed 0x%x\n", ret);
        goto clean;
    }
    ret = km_envelope_update(op_handle, enc, update_len, dec, &dest_len);
    if (ret) {
        KM_TEST_ERR("test dec update failed 0x%x\n", ret);
        goto clean;
    }
    dec_len += dest_len;
    dest_len = get_len - dec_len; //for test short buffer
    ret = km_envelope_finish(op_handle, enc + update_len, enc_len - update_len, dec + dec_len, &dest_len);
    if (ret) {
        KM_TEST_ERR("test dec finish failed 0x%x\n", ret);
        return ret;
    }

    dec_len += dest_len;

#if KM_TEST_DEBUG
    km_test_dump_data("cipher dec dest :", dec, dec_len);
#endif

    if(memcmp(dec, src, test_len)) {
        KM_TEST_ERR("dec result is not correct\n");
        return KM_ERR_GENERIC;
    }
    return KM_SUCCESS;

clean:
    if (km_envelope_finish(op_handle, NULL, 0, NULL, NULL)) {
        KM_TEST_ERR("test enc dec finish failed\n");
    }

    return ret;
}

static uint32_t test_update_short(char *name, uint32_t name_len,
                           uint32_t index)
{
    uint32_t test_len = 0;
    uint32_t dest_len = 0;
    uint8_t enc_array[256] = {0};
    uint8_t *enc = enc_array;
    uint32_t enc_len = 0;
    uint8_t src_array[256] = {0};
    uint8_t *src = src_array;
    uint8_t dec_array[256] = {0};
    uint8_t *dec = dec_array;
    uint32_t dec_len = 0;
    void  *op_handle = NULL;
    uint32_t ret = 0;
    uint8_t *iv = NULL;
    uint32_t iv_len = 0;
    uint32_t enc1_len = update_short[index].update1;
    uint32_t enc2_len = update_short[index].update2;
    uint32_t encl_len = 0;

    uint32_t dec1_len = update_short[index].update1;
    uint32_t dec2_len = update_short[index].update2;
    uint32_t decl_len = 0;
    uint8_t protected_key[16];
    uint32_t protected_key_len = 16;
    km_purpose_type is_enc = 0;

    test_len = UPDATE_TEST_LEN + 1;
    encl_len = test_len - (enc1_len + enc2_len);

    is_enc = KM_PURPOSE_ENCRYPT;
    km_memcpy(src, aes_test_data, test_len);

    iv = usr_iv;
    iv_len = 16;

    ret = km_envelope_begin(&op_handle, name, name_len, iv, iv_len,
            protected_key, &protected_key_len, is_enc);
    if (ret) {
        KM_TEST_ERR("begin failed 0x%x\n", ret);
        goto clean;
    }
    dest_len = 0;
    ret = km_envelope_update(op_handle, src, enc1_len, enc, &dest_len);
    if (ret == KM_ERR_SHORT_BUFFER) {
//        KM_TEST_INF("UPDATE_SHORT: enc update1 len is %ld\n", (unsigned long)dest_len);
        ret = km_envelope_update(op_handle, src, enc1_len, enc, &dest_len);
        if (ret) {
            KM_TEST_ERR("update1 failed 0x%x\n", ret);
            goto clean;
        }
    }
    enc_len += dest_len;
    src += enc1_len;
    dest_len = 0;
    ret = km_envelope_update(op_handle, src, enc2_len, enc + enc_len, &dest_len);
    if (ret == KM_ERR_SHORT_BUFFER) {
//        KM_TEST_INF("UPDATE_SHORT: enc update2 len is %ld\n", (unsigned long)dest_len);
        ret = km_envelope_update(op_handle, src, enc2_len, enc + enc_len, &dest_len);
        if (ret) {
            KM_TEST_ERR("update1 failed 0x%x\n", ret);
            goto clean;
        }
    }
    enc_len += dest_len;
    src += enc2_len;

    dest_len = 256;
    ret = km_envelope_finish(op_handle, src, encl_len, enc + enc_len, &dest_len);
    if (ret) {
        KM_TEST_ERR("enc finish failed 0x%x\n", ret);
        return ret;
    }

    enc_len += dest_len;

#if KM_TEST_DEBUG
    km_test_dump_data("enc dest is :", enc, enc_len);
#endif

    is_enc = KM_PURPOSE_DECRYPT;
    ret = km_envelope_begin(&op_handle, name, name_len, iv, iv_len,
                 protected_key, &protected_key_len, is_enc);
    if (ret) {
        KM_TEST_ERR("begin failed 0x%x\n", ret);
        goto clean;
    }
    dest_len = 0;
    ret = km_envelope_update(op_handle, enc, dec1_len, dec, &dest_len);
    if (ret == KM_ERR_SHORT_BUFFER) {
//        KM_TEST_INF("UPDATE_SHORT: dec update1 len is %ld\n", (unsigned long)dest_len);
        ret = km_envelope_update(op_handle, enc, dec1_len, dec, &dest_len);
        if (ret) {
            KM_TEST_ERR("update1 failed 0x%x\n", ret);
            goto clean;
        }
    }

    dec_len += dest_len;
    enc += dec1_len;
    dest_len = 0;
    ret = km_envelope_update(op_handle, enc, dec2_len, dec + dec_len, &dest_len);
    if (ret == KM_ERR_SHORT_BUFFER) {
//        KM_TEST_INF("UPDATE_SHORT: dec update2 len is %ld\n", (unsigned long)dest_len);
        ret = km_envelope_update(op_handle, enc, dec2_len, dec + dec_len, &dest_len);
        if (ret) {
            KM_TEST_ERR("update1 failed 0x%x\n", ret);
            goto clean;
        }
    }

    dec_len += dest_len;
    enc += dec2_len;
    dest_len = 256;
    decl_len = enc_len - (dec1_len + dec2_len);
    ret = km_envelope_finish(op_handle, enc, decl_len, dec + dec_len, &dest_len);
    if (ret) {
        KM_TEST_ERR("dec finish failed 0x%x\n", ret);
        return ret;
    }

    dec_len += dest_len;

#if KM_TEST_DEBUG
    km_test_dump_data("dec dest is :", dec, dec_len);
#endif

    if (memcmp(dec, src_array, test_len)) {
        KM_TEST_ERR("dec result is not correct\n");
        return KM_ERR_GENERIC;
    }

    return 0;

clean:
    if (km_envelope_finish(op_handle, NULL, 0, NULL, NULL)) {
        KM_TEST_ERR("finish failed\n");
    }

    return ret;
}

//for performance test
uint32_t test_envelope_no_update(char *name, uint32_t name_len,
                               uint8_t *src, uint32_t src_len,
                               uint8_t *dest, uint32_t *dest_len,
                               km_purpose_type is_enc)
{
    km_op_handle_t op_handle = NULL;
    uint8_t *iv = NULL;
    uint8_t iv_len = 0;
    uint32_t ret = 0;
    uint8_t protected_key[16] = { 0 };
    uint32_t protected_key_len = 16;

    iv = usr_iv;
    iv_len = 16;

    ret = km_envelope_begin(&op_handle, name, name_len, iv, iv_len,
            protected_key, &protected_key_len, is_enc);
    if (ret) {
        KM_TEST_ERR("begin failed 0x%x\n", ret);
        return ret;
    }

    ret = km_envelope_finish(op_handle, src, src_len, dest, dest_len);
    if (ret) {
        KM_TEST_ERR("test enc_dec finish failed 0x%x\n", ret);
        return ret;
    }

#if KM_TEST_DEBUG
    km_test_dump_data("cipher enc/dec dest :", dest, *dest_len);
#endif

    return ret;
}

uint32_t km_envelope_test()
{
    uint32_t ret = 0;
    KM_TEST_INF("start test import/generate\n");
//    ret = test_import(NAME, NAME_LEN, KM_AES);
    ret = test_generate(AES_GEN_NAME, AES_GEN_NAME_LEN, KM_AES, 128);
    if (ret && ret != KM_ERR_ACCESS_CONFLICT) {
        KM_TEST_ERR("test import/generate failed 0x%x\n", ret);
        return ret;
    }

    ret = test_envelope_enc_dec(AES_GEN_NAME, AES_GEN_NAME_LEN);
    if (ret) {
        KM_TEST_ERR("test enc dec failed 0x%x\n", ret);
        return ret;
    }

    ret = test_delete(AES_GEN_NAME, AES_GEN_NAME_LEN);
    if (ret) {
        KM_TEST_ERR("test delete failed 0x%x\n", ret);
        return ret;
    }

    return ret;
}

uint32_t km_envelope_short_test()
{
    uint32_t ret = 0;
    uint32_t i = 0;

    ret = test_import(AES_IM_NAME, AES_IM_NAME_LEN, KM_AES);
    if (ret && ret != KM_ERR_ACCESS_CONFLICT) {
        KM_TEST_ERR("test import failed 0x%x\n", ret);
        return ret;
    }

    for (i = 0; i < short_buf_test_count; i++) {
        ret = test_envelope_short(AES_IM_NAME, AES_IM_NAME_LEN, i);
        if (ret) {
            KM_TEST_ERR("test enc dec failed 0x%x\n", ret);
            goto clean;
        }
        KM_TEST_INF("**** test %d index success ****\n", i);
    }

clean:
    if (test_delete(AES_IM_NAME, AES_IM_NAME_LEN)) {
        KM_TEST_ERR("test delete failed 0x%x\n", ret);
    }

    return ret;
}

uint32_t km_envelope_update_short_test()
{
    uint32_t ret = 0;
    uint32_t i = 0;

    ret = test_import(AES_IM_NAME, AES_IM_NAME_LEN, KM_AES);
    if (ret && ret != KM_ERR_ACCESS_CONFLICT) {
        KM_TEST_ERR("test import failed 0x%x\n", ret);
        return ret;
    }

    for (i = 0; i < update_short_count; i++) {
        ret = test_update_short(AES_IM_NAME, AES_IM_NAME_LEN, i);
        if (ret) {
            KM_TEST_ERR("test enc dec failed 0x%x\n", ret);
            goto clean;
        }
        KM_TEST_INF("**** test %d index success ****\n", i);
    }

    ret = test_delete(AES_IM_NAME, AES_IM_NAME_LEN);
    if (ret) {
        KM_TEST_ERR("test delete failed\n");
        return ret;
    }

    return 0;

clean:
    if (test_delete(AES_IM_NAME, AES_IM_NAME_LEN)) {
        KM_TEST_ERR("test delete failed\n");
    }

    return ret;
}

uint32_t km_envelope_update_test()
{
    uint32_t ret = 0;

    ret = test_import(AES_IM_NAME, AES_IM_NAME_LEN, KM_AES);
    if (ret && ret != KM_ERR_ACCESS_CONFLICT) {
        KM_TEST_ERR("test import failed 0x%x\n", ret);
        return ret;
    }

    ret = test_update(AES_IM_NAME, AES_IM_NAME_LEN);
    if (ret) {
        KM_TEST_ERR("test enc update failed 0x%x\n", ret);
        return ret;
    }

    ret = test_delete(AES_IM_NAME, AES_IM_NAME_LEN);
    if (ret) {
        KM_TEST_ERR("test delete failed 0x%x\n", ret);
        return ret;
    }

    return ret;
}

int km_envelope_whole_test()
{
    int ret = 0;

    ret = km_envelope_test();
    if (ret) {
        KM_TEST_ERR("km_envelope_test failed\n");
        return ret;
    }
    KM_TEST_INF("\n<<<<<< km envelope test success ! >>>>>>>>\n");

    ret = km_envelope_short_test();
    if (ret) {
        KM_TEST_ERR("km_envelope_short_test failed\n");
        return ret;
    }
    KM_TEST_INF("\n<<<<<< ks envelope short test success ! >>>>>>>>\n");

    ret = km_envelope_update_test();
    if (ret) {
        KM_TEST_ERR("ks_envelope_update_test failed\n");
        return ret;
    }
    KM_TEST_INF("\n<<<<<< ks envelope update test success ! >>>>>>>>\n");

    ret = km_envelope_update_short_test();
    if (ret) {
        KM_TEST_ERR("km_envelope_update_short_test failed\n");
        return ret;
    }

    return 0;
}

//test 1K data
int km_envelope_perf_test(uint32_t test_count)
{
    uint8_t aes_src[PERF_LEN];
    uint8_t aes_enc[PERF_LEN] = {0};
    uint8_t aes_dec[PERF_LEN] = {0};
    uint32_t aes_src_len = PERF_LEN;
    uint32_t aes_enc_len = PERF_LEN;
    uint32_t aes_dec_len = PERF_LEN;
    km_purpose_type is_enc = 0;
    uint32_t i = 0;
    uint32_t ret = 0;
    double total_time, av_time;
    struct timeval start_tv, end_tv;

    KM_TEST_INF("******************envelope perf test start*******************\n");
    ret = test_generate(AES_GEN_NAME, AES_GEN_NAME_LEN, KM_AES, 128);
    if (ret && ret != KM_ERR_ACCESS_CONFLICT) {
        KM_TEST_ERR("test import/generate failed 0x%x\n", ret);
        return ret;
    }

    for (i = 0; i < PERF_LEN / 64; i++) {
        km_memcpy(aes_src + i * 64, aes_test_data, aes_src_len);
    }

    gettimeofday(&start_tv, NULL);
    is_enc = KM_PURPOSE_ENCRYPT;
    for (i = 0; i < test_count; i++) {
        ret = test_envelope_no_update(AES_GEN_NAME, AES_GEN_NAME_LEN,
                aes_src, aes_src_len, aes_enc, &aes_enc_len, is_enc);
        if (ret) {
            KM_TEST_ERR("test enc dec failed 0x%x\n", ret);
            test_delete(AES_GEN_NAME, AES_GEN_NAME_LEN);
            return ret;
        }
    }

    gettimeofday(&end_tv, NULL);
    total_time = (end_tv.tv_usec - start_tv.tv_usec)/1000 +
                 (end_tv.tv_sec - start_tv.tv_sec) * 1000;

    av_time = total_time / test_count;
    KM_TEST_INF("envelope enc total time: %fms, av_time: %fms\n", total_time, av_time);

    gettimeofday(&start_tv, NULL);
    is_enc = KM_PURPOSE_DECRYPT;
    for (i = 0; i < test_count; i++) {
        ret = test_envelope_no_update(AES_GEN_NAME, AES_GEN_NAME_LEN,
                aes_enc, aes_enc_len, aes_dec, &aes_dec_len, is_enc);
        if (ret) {
            KM_TEST_ERR("test enc dec failed 0x%x\n", ret);
            test_delete(AES_GEN_NAME, AES_GEN_NAME_LEN);
            return ret;
        }
    }

    gettimeofday(&end_tv, NULL);
    if (aes_dec_len != aes_src_len &&
        memcmp(aes_src, aes_dec, aes_src_len)) {
        KM_TEST_INF("perf test aes decrypt wrong result\n");
        return KM_ERR_GENERIC;
    }
    total_time = (end_tv.tv_usec - start_tv.tv_usec)/1000 +
                 (end_tv.tv_sec - start_tv.tv_sec) * 1000;

    av_time = total_time / test_count;
    KM_TEST_INF("envelope dec total time: %fms, av_time: %fms\n", total_time, av_time);

    ret = test_delete(AES_GEN_NAME, AES_GEN_NAME_LEN);
    if (ret) {
        KM_TEST_ERR("EEEEE test_delete failed\n");
        return ret;
    }

    return ret;
}

