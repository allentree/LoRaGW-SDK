#include <dbus/dbus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "keychain.h"

#define SEC_TEST_WELL_KNOWN_NAME      "iot.gateway.security.test"
#define CASE_BLANK 1000
#define CASE_NOT_BLANK 1001

// two client
// case 1: store: client1(key) get: client2(key)

static char *test_sec_sst_get(DBusConnection *connection, char *key);
static int test_sec_sst_store(DBusConnection *connection, char *key, char *secret);

//单个进程反复读写同一个key name 1000次，每个secret 相同
void test_case1(DBusConnection *connection)
{
    int loop = 0;
    int ret = 0;
    char *key = "test_key";
    char *secret = "test_secret";
    char *secResult = NULL;
    printf("\n单个进程反复读写同一个key name 1000次，每个secret 相同\n");
    for(loop = 0; loop < 1000; loop++)
    {
        ret = test_sec_sst_store(connection, key, secret);
        assert(ret == 0);
        secResult = test_sec_sst_get(connection, key);
        assert(secResult);
        assert(0 == strcmp(secResult,secret));
        if (secResult) {
            free(secResult);
            secResult = NULL;
        }
        usleep(50*1000);
    }
    printf("The %s is: OK\n",__func__);
}

//单个进程反复读写同一个key name 1000次，每个secret 不同
void test_case2(DBusConnection *connection)
{
    int loop = 0;
    int ret = 0;
    char *key = "test_key";
    char secret[1000] = {0};
    char *secResult = NULL;
    printf("\n单个进程反复读写同一个key name 1000次，每个secret 不同\n");
    for(loop = 0; loop < 1000; loop++)
    {
        snprintf(secret, 1000, "test_key_%d",loop);
        ret = test_sec_sst_store(connection, key, secret);
        assert(ret == 0);
        secResult = test_sec_sst_get(connection, key);
        assert(secResult);
        assert(0 == strcmp(secResult,secret));
        if (secResult) {
            free(secResult);
            secResult = NULL;
        }
        usleep(50*1000);
    }
    printf("The %s is: OK\n",__func__);
}

//单个进程反复读写同一个key name 1000次，每次key name不同
void test_case3(DBusConnection *connection)
{
    int loop = 0;
    int ret = 0;
    char key[1000] = {0};
    char secret[1000] = {0};
    char *secResult = NULL;
    printf("\n单个进程反复读写同一个key name 1000次，每次key name不同\n");
    for(loop = 0; loop < 1000; loop++)
    {
        snprintf(key, 1000, "test_secret_%d",loop);
        snprintf(secret, 1000, "test_key_%d",loop);
        printf("key is %s\n", key);
        ret = test_sec_sst_store(connection, key, secret);
        assert(ret == 0);
        secResult = test_sec_sst_get(connection, key);
        assert(secResult);
        assert(0 == strcmp(secResult,secret));
        if (secResult) {
            free(secResult);
            secResult = NULL;
        }
        usleep(50*1000);
    }
    printf("The %s is: OK\n",__func__);
}

//单个进程反复读100个key name 100次
void test_case4(DBusConnection *connection)
{
    int loop = 0;
    int ret = 0;
    int i = 0;
    char key[1000] = {0};
    char secret[1000] = {0};
    char *secResult = NULL;
    printf("\n单个进程反复读100个key name 100次\n");
    for(loop = 0; loop < 100; loop++)
    {
        for(i = 0; i < 100; i++)
        {
            snprintf(key, 1000, "test_secret_%d",i);
            snprintf(secret, 1000, "test_key_%d",i);
            printf("key is %s\n", key);
            secResult = test_sec_sst_get(connection, key);
            assert(secResult);
            assert(0 == strcmp(secResult,secret));
            if (secResult) {
                free(secResult);
                secResult = NULL;
            }
            usleep(50*1000);
        }
    }
    printf("The %s is: OK\n",__func__);
}

int main(void)
{
    DBusConnection *connection;
    DBusError error;
    dbus_bool_t ret;
    DBusObjectPathVTable vtable;
    uint32_t kc_ret = 0;

    dbus_error_init(&error);

    connection = dbus_connection_open(bus_address, &error);
    assert(connection);

    ret = dbus_bus_register(connection, &error);
    assert(ret);

    ret = dbus_bus_request_name(connection, SEC_TEST_WELL_KNOWN_NAME, 0, &error);
    printf("request name('%s') %s\n", SEC_TEST_WELL_KNOWN_NAME, ret == 1 ? "success" : "failed");

    kc_ret = kc_init();
    assert(kc_ret == 0);

    test_case1(connection);
    test_case2(connection);
    test_case3(connection);
    test_case4(connection);

    kc_destroy();

    dbus_connection_unref(connection);
    return 0;
}

static char *test_sec_sst_get(DBusConnection *connection, char *key) {
    uint8_t *secret = NULL;
    uint32_t secret_len = 0;
    kc_key_type_t key_type = 0;
    uint32_t ret = 0;

    ret = kc_get_item(key, secret, &secret_len, &key_type);
    if (ret != KC_ERROR_SHORT_BUFFER) {
        printf("%s(%d) get item len failed 0x%x\n", __FUNCTION__, __LINE__, ret);
        return NULL;
    }

    secret_len += 1;
    secret = malloc(secret_len);
    if (!secret) {
        printf("%s(%d) malloc secret failed\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    memset(secret, 0, secret_len);

    ret = kc_get_item(key, secret, &secret_len, &key_type);
    if (ret) {
        printf("%s(%d) get item failed 0x%x\n", __FUNCTION__, __LINE__, ret);
        free(secret);
        return NULL;
    }

    return secret;
}

static int test_sec_sst_store(DBusConnection *connection, char *key, char *secret) {
    kc_key_type_t key_type = 0;

    int ret = kc_add_item(key, secret, strlen(secret), 0);
    
    return ret;
}
