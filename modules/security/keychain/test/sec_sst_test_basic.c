#include <dbus/dbus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "keychain.h"

#define SEC_TEST_WELL_KNOWN_NAME      "iot.gateway.security.test.basic"

#define TEST_BASIC_KEY "kc_test_basic_key"
#define TEST_BASIC_SECRET "kc_test_basic_secret"
#define TEST_BASIC_SECRET_LEN 20
#define TEST_BASIC_SECRET_SHORT_LEN 19

static void test_sec_sst_store();
static void test_sec_sst_get();

typedef struct _store_test_params_t {
    char *name;
    uint8_t *secret;
    uint32_t secret_len;
    kc_key_type_t key_type;
    uint32_t exp_ret;
} store_test_params_t;

typedef struct _get_test_params_t {
    char *name;
    uint8_t secret_null;
    uint32_t secret_len;
    uint32_t exp_ret;
} get_test_params_t;

store_test_params_t store_params[] = {
    {NULL, NULL, 0, 0, KC_ERROR_BAD_PARAMETERS},
    {NULL, TEST_BASIC_SECRET, TEST_BASIC_SECRET_LEN, 0, KC_ERROR_BAD_PARAMETERS},
    {TEST_BASIC_KEY, NULL, 0, 0, KC_ERROR_BAD_PARAMETERS},
    {TEST_BASIC_KEY, TEST_BASIC_SECRET, TEST_BASIC_SECRET_LEN, 0, KC_SUCCESS},
};

get_test_params_t get_params[] = {
    {NULL, 0, 0, KC_ERROR_BAD_PARAMETERS},
    {TEST_BASIC_KEY, 1, 1, KC_ERROR_BAD_PARAMETERS}, //secret = NULL
    {TEST_BASIC_KEY, 1, 0, KC_ERROR_SHORT_BUFFER},
    {TEST_BASIC_KEY, 0, TEST_BASIC_SECRET_SHORT_LEN, KC_ERROR_SHORT_BUFFER},
    {TEST_BASIC_KEY, 0, TEST_BASIC_SECRET_LEN, KC_SUCCESS},
    {TEST_BASIC_KEY, 0, 1024, KC_SUCCESS},
    {TEST_BASIC_SECRET, 0, TEST_BASIC_SECRET_LEN, KC_ERROR_ITEM_NOT_FOUND},
};

int main(void)
{
    DBusConnection *connection;
    DBusError error;
    dbus_bool_t ret;
    DBusObjectPathVTable vtable;
    uint32_t kc_ret;

    dbus_error_init(&error);

    connection = dbus_connection_open(bus_address, &error);
    assert(connection);

    ret = dbus_bus_register(connection, &error);
    assert(ret);

    ret = dbus_bus_name_has_owner(connection, SEC_TEST_WELL_KNOWN_NAME, &error);
    assert(ret == FALSE);

    ret = dbus_bus_request_name(connection, SEC_TEST_WELL_KNOWN_NAME, 0, &error);
    printf("request name('%s') %s\n", SEC_TEST_WELL_KNOWN_NAME, ret == 1 ? "success" : "failed");
    assert(DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER == ret);

    kc_ret = kc_init();
    assert(kc_ret == 0);

    test_sec_sst_store();
    test_sec_sst_get();
    kc_destroy();

    while (dbus_connection_get_is_connected(connection)) {
        dbus_connection_read_write_dispatch(connection, 1000);
    }

    return 0;
}

static void test_sec_sst_store()
{
    char *name;
    uint8_t *secret;
    uint32_t secret_len = 0;
    kc_key_type_t key_type;
    uint32_t ret;
    int size_store_case = (int)(sizeof(store_params)/sizeof(store_params[0]));
    store_test_params_t store_param;
    int i = 0;

    printf("test_sec_sst_store.\n");
    printf("store_case size %d\n", size_store_case);

    for (i = 0;i < size_store_case; i++) {
        store_param = store_params[i];
        printf("\ncase %d: ", i);

        name = store_param.name;
        secret = store_param.secret;
        secret_len = store_param.secret_len;
        key_type = store_param.key_type;
        /*
        ret = kc_add_item(name, secret, secret_len, key_type);
        if (ret != store_param.exp_ret) {
            printf("add item return wrong\n");
            printf("test_sec_sst_store[%d] failed\n", i);
            return;
        }
        */
        ret = kc_add_global_item(name, secret, secret_len, key_type);
        if(ret != store_param.exp_ret) {
            printf("add item return wrong\n");
            printf("test_sec_sst_store[%d] failed\n", i);
            return;
        }

        printf("test_sec_sst_store[%d] success\n", i);
    }
    printf("test_sec_sst_store total %d case success\n\n", size_store_case);
}

static void test_sec_sst_get()
{
    char *name = NULL;
    uint8_t *secret = NULL;
    uint32_t secret_len = 0;
    kc_key_type_t key_type = 0;
    int i = 0;
    int size_get_case = (int)(sizeof(get_params)/sizeof(get_params[0]));
    get_test_params_t get_param;

    printf("test_sec_sst_get, ");
    printf("size_get_case : %d\n", size_get_case);

    for (i = 0; i < size_get_case; i++) {
        printf("\ncase %d: ", i);
        get_param = get_params[i];

        name = get_param.name;
        if (get_param.secret_null) {
            secret = NULL;
        } else {
            secret = malloc(1024);
            memset(secret, 0, 1024);
        }
        secret_len = get_param.secret_len;
        /*
        if (kc_get_item(name, secret, &secret_len, &key_type) != get_param.exp_ret) {
            printf("test_sec_sst_get[%d] failed\n", i);
            goto clean;
        }
        */
        if (kc_get_global_item(name, secret, &secret_len, &key_type) != get_param.exp_ret) {
            printf("test_sec_sst_get[%d] failed\n", i);
            goto clean;
        }

        if (get_param.exp_ret == KC_ERROR_SHORT_BUFFER) {
            if (secret_len != TEST_BASIC_SECRET_LEN) {
                printf("test_sec_sst_get[%d] failed wrong len\n", i);
                goto clean;
            }
        }

        if (get_param.exp_ret == KC_SUCCESS) {
            if (secret_len != TEST_BASIC_SECRET_LEN) {
                printf("test_sec_sst_get[%d] failed wrong len %d\n", i, secret_len);
                goto clean;
            }

            if (memcmp(secret, TEST_BASIC_SECRET, secret_len)) {
                printf("test_sec_sst_get[%d] failed wrong secret %s\n", i, secret);
                goto clean;
            } else {
                printf("secret is %s\n", secret);
            }
        }

        if (secret) {
            free(secret);
            secret = NULL;
        }
        
        printf("test_sec_sst_get[%d] success\n", i);
    }
    printf("test_sec_sst_get success. \n\n");
    return;

clean:
    if (secret) {
        free(secret);
        secret = NULL;
    }
}

