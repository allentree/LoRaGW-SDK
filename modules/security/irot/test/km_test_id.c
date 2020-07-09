#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include "km.h"
#include "km_test_comm.h"
#include "km_test_dbg.h"

uint32_t test_get_id2()
{
    uint32_t ret;
    uint8_t id_value[25]; //'\0'
    uint32_t id2_len = 0;

    ret = km_get_id2(NULL, &id2_len);
    if (ret != KM_ERR_SHORT_BUFFER || id2_len != 24) {
        KM_TEST_ERR("fail to get ID len 0x%x!\n", ret);
        return ret;
    }

    ret = km_get_id2(id_value, &id2_len);
    if (ret || id2_len != 24) {
        KM_TEST_ERR("fail to get ID!\n");
        return KM_ERR_GENERIC;
    }
    id_value[24] = '\0';
    KM_TEST_INF("id2_len is %d, ID2 ID: %s\n", id2_len, id_value);

    return ret;
}

uint32_t test_set_get_id2()
{
    uint32_t ret;
    uint8_t id_value[25]; //'\0'
    uint32_t id2_len = 24;
    char *test_id = "0FFFFFFFFFFFFA6F67AB700";

    ret = km_set_id2((uint8_t *)test_id, id2_len);
    if (ret) {
        KM_TEST_ERR("fail to set ID!\n");
        return ret;
    }

    ret = km_get_id2(id_value, &id2_len);
    if (ret) {
        KM_TEST_ERR("fail to get ID!\n");
        return ret;
    }
    id_value[24] = '\0';
    KM_TEST_INF("id2_len is %d, ID2 ID: %s\n", id2_len, id_value);

    return ret;
}

uint32_t km_get_attestation_test()
{
    uint8_t *id = NULL;
    uint32_t id_len = 0;
    uint32_t tmp_id_len = 0;
    uint32_t ret = 0;

    ret = km_get_attestation(id, &id_len);
    if (ret != KM_ERR_SHORT_BUFFER) {
        KM_TEST_ERR("km get attestation len failed 0x%x\n", ret);
        return ret;
    }

    id = km_malloc(id_len + 1);
    tmp_id_len = id_len + 1;
    ret = km_get_attestation(id, &tmp_id_len);
    if (ret || tmp_id_len != id_len) {
        KM_TEST_ERR("km get attestation failed 0x%x, tmp_len %d, id_len %d\n",
                ret, tmp_id_len, id_len);
        goto clean;
    }
#if KM_TEST_DEBUG
    km_test_dump_data("attestation id is :", id, id_len);
#endif /* KM_TEST_DEBUG */
clean:
    if (id) {
        km_free(id);
        id = NULL;
    }

    return ret;
}
