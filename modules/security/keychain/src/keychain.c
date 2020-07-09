#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dbus/dbus.h>
#include <errno.h>
#include <pthread.h>
#include "tfs_log.h"
#include "keychain.h"
#include "irot.h"
#include "kc_private.h"

static DBusConnection *connection = NULL;
static pthread_mutex_t mutex;
static pthread_mutex_t domain_mutex;
char proc_domain_name[MAX_DOMAIN_NAME_LEN + 1] = { 0 };

uint32_t kc_init()
{
    dbus_bool_t ret;
    DBusError error;

    pthread_mutex_init(&mutex, NULL);

    dbus_error_init(&error);

    pthread_mutex_lock(&mutex);
    connection = dbus_connection_open_private(bus_address, &error);
    if (connection == NULL) {
        dbus_error_parse(error);
        goto clean;
    }

    ret = dbus_bus_register(connection, &error);
    dbus_error_parse(error);
    if (ret == FALSE) {
        goto clean;
    }
    pthread_mutex_unlock(&mutex);
    pthread_mutex_init(&domain_mutex, NULL);

    return KC_SUCCESS;

clean:
    pthread_mutex_unlock(&mutex);
    pthread_mutex_destroy(&mutex);

    return KC_ERROR_GENERIC;
}

void kc_destroy()
{
    pthread_mutex_destroy(&domain_mutex);
    pthread_mutex_lock(&mutex);
    if (connection) {
        dbus_connection_close(connection);
        connection = NULL;
    }
    pthread_mutex_unlock(&mutex);

    pthread_mutex_destroy(&mutex);
}

// add item
uint32_t kc_add_item(const char *key_name, const uint8_t *key_sec,
        uint32_t key_sec_len, kc_key_type_t key_type)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    int result = 0;
    char name[FILENAME_MAX + 1];
    int shm_id = 0;
    void *buf = NULL;
    int total_size = 0;
    size_t name_size = 0;
    size_t key_size = 0;
    size_t secret_size = 0;
    int len = 0;
    uint32_t domain_name_len = 0;

    if (!key_name || !key_sec || !key_sec_len ||
        key_type > KEY_CHAIN_USERDATA) {
        log_e(TAG, "bad null params\n");
        return KC_ERROR_BAD_PARAMETERS;
    }

    dbus_error_init(&error);
    msgQuery = dbus_message_new_method_call(
                           SEC_WELL_KNOWN_NAME,
                           SEC_SST_OBJECT_PATH,
                           SEC_SST_INTERFACE_NAME,
                           KC_ADD_ITEM);

    //get the process name
    memset(name, 0, FILENAME_MAX);
    len = readlink("/proc/self/exe", name, FILENAME_MAX);
    if (len <= 0) {
        log_e(TAG, "readlink fail\n");
        result = KC_ERROR_GENERIC;
        goto clean;
    }
    name_size = strlen(name) + 1;
    key_size = strlen(key_name) + 1;
    secret_size = key_sec_len;
    pthread_mutex_lock(&domain_mutex);
    domain_name_len = strlen(proc_domain_name);
    if (domain_name_len) {
        total_size = name_size + key_size + secret_size + domain_name_len + 1; //1 \0 for domain_name
    } else {
        total_size = name_size + key_size + secret_size;
    }
    pthread_mutex_unlock(&domain_mutex);

    KC_SHM_CREATE(total_size, shm_id);
    if (shm_id < 0) {
        log_e(TAG, "shm create failed errno: %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean;
    }
    KC_SHM_MMAP(shm_id, buf);
    if (buf == NULL) {
        log_e(TAG, "shm mmap failed\n");
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean1;
    }
    memcpy(buf, name, name_size);
    memcpy(buf + name_size, key_name, key_size);
    memcpy(buf + name_size + key_size, key_sec, secret_size);

    pthread_mutex_lock(&domain_mutex);
    if (domain_name_len)
        memcpy(buf + name_size + key_size + secret_size, proc_domain_name, domain_name_len + 1);
    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, &key_type,
                             DBUS_TYPE_INT32, &secret_size,
                             DBUS_TYPE_INT32, &domain_name_len,
                             DBUS_TYPE_INVALID);
    pthread_mutex_unlock(&domain_mutex);
    do {
        pthread_mutex_lock(&mutex);
        if (!connection) {
            pthread_mutex_unlock(&mutex);
            log_e(TAG, "please first call kc_init\n");
            result = KC_ERROR_GENERIC;
            break;
        }
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KC_ERROR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error, DBUS_TYPE_INT32, &result, DBUS_TYPE_INVALID);

        dbus_message_unref(msgReply);
    } while(0);

    KC_SHM_MUNMAP(buf);
clean1:
    KC_SHM_DESTROY(shm_id);
clean:
    dbus_message_unref(msgQuery);

    return result;
}

//  Searching for Keychain Items
uint32_t kc_get_item(const char *key_name, uint8_t *key_sec,
        uint32_t *key_sec_len, kc_key_type_t *key_type)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    int result = 0;
    char name[FILENAME_MAX + 1];
    int shm_id = 0;
    void *in_buf = NULL;
    int total_size = 0;
    int out_len = 0;
    size_t name_size = 0;
    size_t key_size = 0;
    int len = 0;
    uint32_t domain_name_len = 0;

    if (!key_name || !key_sec_len || (!key_sec && *key_sec_len)) {
        log_e(TAG, "bad null params\n");
        return KC_ERROR_BAD_PARAMETERS;
    }

    dbus_error_init(&error);

    msgQuery = dbus_message_new_method_call(
                           SEC_WELL_KNOWN_NAME,
                           SEC_SST_OBJECT_PATH,
                           SEC_SST_INTERFACE_NAME,
                           KC_GET_ITEM);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        return KC_ERROR_GENERIC;
    }

    memset(name, 0, FILENAME_MAX);
    len = readlink("/proc/self/exe", name, FILENAME_MAX);
    if (len <= 0) {
        log_e(TAG, "readlink fail\n");
        result = KC_ERROR_GENERIC;
        goto clean1;
    }

    name_size = len + 1;
    key_size = strlen(key_name) + 1;

    pthread_mutex_lock(&domain_mutex);
    domain_name_len = strlen(proc_domain_name);
    if (domain_name_len) {
        total_size = name_size + key_size + *key_sec_len + domain_name_len + 1;
    } else {
        total_size = name_size + key_size + *key_sec_len;
    }
    pthread_mutex_unlock(&domain_mutex);

    KC_SHM_CREATE(total_size, shm_id);
    if (shm_id < 0) {
        log_e(TAG, "shm create failed errno: %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean1;
    }

    KC_SHM_MMAP(shm_id, in_buf);
    if (in_buf == NULL) {
        log_e(TAG, "shm mmap failed errno %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean2;
    }
    memcpy(in_buf, name, name_size);
    memcpy(in_buf + name_size, key_name, key_size);
    memset(key_sec, 0, *key_sec_len);

    pthread_mutex_lock(&domain_mutex);
    if (domain_name_len)
        memcpy(in_buf + name_size + key_size + *key_sec_len, proc_domain_name, domain_name_len + 1);
    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, key_sec_len,
                             DBUS_TYPE_INT32, &domain_name_len,
                             DBUS_TYPE_INVALID);
    pthread_mutex_unlock(&domain_mutex);

    do {
        pthread_mutex_lock(&mutex);
        if (!connection) {
            pthread_mutex_unlock(&mutex);
            log_e(TAG, "please first call kc_init\n");
            result = KC_ERROR_GENERIC;
            break;
        }
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KC_ERROR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, &out_len,
                DBUS_TYPE_INT32, key_type,
                DBUS_TYPE_INVALID);
        if (result == 0) {
            memcpy(key_sec, in_buf + name_size + key_size, out_len);
            *key_sec_len = out_len;
        } else if (result == KC_ERROR_SHORT_BUFFER) {
            log_e(TAG, "short buffer %d : %d\n", *key_sec_len, out_len);
            *key_sec_len = out_len;
        }

        dbus_message_unref(msgReply);
    } while(0);

    KC_SHM_MUNMAP(in_buf);
clean2:
    KC_SHM_DESTROY(shm_id);
clean1:
    dbus_message_unref(msgQuery);

    return result;
}
uint32_t kc_delete_global_item(const char *key_name)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    int result = 0;
    char name[FILENAME_MAX + 1];
    int shm_id = 0;
    void *in_buf = NULL;
    int total_size = 0;
    int out_len = 0;
    size_t name_size = 0;
    size_t key_size = 0;
    int len = 0;

    if (!key_name) {
        log_e(TAG, "bad null params\n");
        return KC_ERROR_BAD_PARAMETERS;
    }

    dbus_error_init(&error);

    msgQuery = dbus_message_new_method_call(
                           SEC_WELL_KNOWN_NAME,
                           SEC_SST_OBJECT_PATH,
                           SEC_SST_INTERFACE_NAME,
                           KC_DELETE_GLOBAL_ITEM);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        return KC_ERROR_GENERIC;
    }

    memset(name, 0, FILENAME_MAX);
    len = readlink("/proc/self/exe", name, FILENAME_MAX);
    if (len <= 0) {
        log_e(TAG, "readlink fail\n");
        result = KC_ERROR_GENERIC;
        goto clean1;
    }

    name_size = len + 1;
    key_size = strlen(key_name) + 1;
    total_size = name_size + key_size;

    KC_SHM_CREATE(total_size, shm_id);
    if (shm_id < 0) {
        log_e(TAG, "shm create failed errno: %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean1;
    }

    KC_SHM_MMAP(shm_id, in_buf);
    if (in_buf == NULL) {
        log_e(TAG, "shm mmap failed errno %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean2;
    }
    memcpy(in_buf, name, name_size);
    memcpy(in_buf + name_size, key_name, key_size);

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INVALID);
    do {
        pthread_mutex_lock(&mutex);
        if (!connection) {
            pthread_mutex_unlock(&mutex);
            log_e(TAG, "please first call kc_init\n");
            result = KC_ERROR_GENERIC;
            break;
        }
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KC_ERROR_GENERIC;
            break;
        }
        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INVALID);

        dbus_message_unref(msgReply);
    } while(0);

    KC_SHM_MUNMAP(in_buf);
clean2:
    KC_SHM_DESTROY(shm_id);
clean1:
    dbus_message_unref(msgQuery);

    return result;
}

uint32_t kc_delete_item(const char *key_name)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    int result = 0;
    char name[FILENAME_MAX + 1];
    int shm_id = 0;
    void *in_buf = NULL;
    int total_size = 0;
    int out_len = 0;
    size_t name_size = 0;
    size_t key_size = 0;
    int len = 0;
    uint32_t domain_name_len = 0;

    if (!key_name) {
        log_e(TAG, "bad null params\n");
        return KC_ERROR_BAD_PARAMETERS;
    }

    dbus_error_init(&error);

    msgQuery = dbus_message_new_method_call(
                           SEC_WELL_KNOWN_NAME,
                           SEC_SST_OBJECT_PATH,
                           SEC_SST_INTERFACE_NAME,
                           KC_DELETE_ITEM);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        return KC_ERROR_GENERIC;
    }

    memset(name, 0, FILENAME_MAX);
    len = readlink("/proc/self/exe", name, FILENAME_MAX);
    if (len <= 0) {
        log_e(TAG, "readlink fail\n");
        result = KC_ERROR_GENERIC;
        goto clean1;
    }

    name_size = len + 1;
    key_size = strlen(key_name) + 1;

    pthread_mutex_lock(&domain_mutex);
    domain_name_len = strlen(proc_domain_name);
    if (domain_name_len) {
        total_size = name_size + key_size + domain_name_len + 1;
    } else {
        total_size = name_size + key_size;
    }
    pthread_mutex_unlock(&domain_mutex);

    KC_SHM_CREATE(total_size, shm_id);
    if (shm_id < 0) {
        log_e(TAG, "shm create failed errno: %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean1;
    }

    KC_SHM_MMAP(shm_id, in_buf);
    if (in_buf == NULL) {
        log_e(TAG, "shm mmap failed errno %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean2;
    }
    memcpy(in_buf, name, name_size);
    memcpy(in_buf + name_size, key_name, key_size);

    pthread_mutex_lock(&domain_mutex);
    if (domain_name_len)
        memcpy(in_buf + name_size + key_size, proc_domain_name, domain_name_len + 1);
    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, &domain_name_len,
                             DBUS_TYPE_INVALID);
    pthread_mutex_unlock(&domain_mutex);

    do {
        pthread_mutex_lock(&mutex);
        if (!connection) {
            pthread_mutex_unlock(&mutex);
            log_e(TAG, "please first call kc_init\n");
            result = KC_ERROR_GENERIC;
            break;
        }
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KC_ERROR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INVALID);

        dbus_message_unref(msgReply);
    } while(0);

    KC_SHM_MUNMAP(in_buf);
clean2:
    KC_SHM_DESTROY(shm_id);
clean1:
    dbus_message_unref(msgQuery);

    return result;
}

//update
uint32_t kc_update_item(const char *key_name, const uint8_t *key_sec, uint32_t key_sec_len);

uint32_t kc_encrypt_data(const uint8_t *data, uint32_t data_len,
        const char *file_path, uint8_t *key, uint32_t *key_len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint32_t file_size = 0;
    uint8_t *tmp_buf = NULL;
    uint32_t result = 0;
    uint32_t total_size = 0;

    if (!data || !data_len || !file_path || !key_len || (!key && *key_len)) {
        return KC_ERROR_BAD_PARAMETERS;
    }

    dbus_error_init(&error);
    msgQuery = dbus_message_new_method_call(
                           SEC_WELL_KNOWN_NAME,
                           SEC_SST_OBJECT_PATH,
                           SEC_SST_INTERFACE_NAME,
                           KC_ENCRYPT_DATA);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        return KC_ERROR_GENERIC;
    }

    file_size = strlen(file_path) + 1;
    total_size = data_len + *key_len + file_size;

    KC_SHM_CREATE(total_size, shm_id);
    if (shm_id < 0) {
        log_e(TAG, "shm create failed errno: %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean1;
    }

    KC_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        log_e(TAG, "shm mmap failed errno %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean2;
    }
    memcpy(shm_buf, data, data_len);
    tmp_buf = shm_buf + data_len;
    memcpy(tmp_buf, file_path, file_size);
    tmp_buf += file_size;
    memset(key, 0, *key_len);

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, &data_len,
                             DBUS_TYPE_INT32, key_len,
                             DBUS_TYPE_INVALID);

    do {
        pthread_mutex_lock(&mutex);
        if (!connection) {
            pthread_mutex_unlock(&mutex);
            log_e(TAG, "please first call kc_init\n");
            result = KC_ERROR_GENERIC;
            break;
        }
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KC_ERROR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, key_len, DBUS_TYPE_INVALID);
        if (result == 0) {
            memcpy(key, tmp_buf, *key_len);
        } else if (result == KC_ERROR_SHORT_BUFFER) {
            log_e(TAG, "short buffer need %d\n", *key_len);
        }

        dbus_message_unref(msgReply);
    } while(0);

    KC_SHM_MUNMAP(shm_buf);
clean2:
    KC_SHM_DESTROY(shm_id);
clean1:
    dbus_message_unref(msgQuery);

    return result;
}

uint32_t kc_decrypt_data(const char *file_path, uint8_t *key,
        uint32_t key_len, uint8_t *data, uint32_t *data_len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint32_t file_size = 0;
    uint8_t *tmp_buf = NULL;
    uint32_t result = 0;
    uint32_t total_size = 0;

    if (!key || !key_len || !file_path || !data_len) {
        return KC_ERROR_BAD_PARAMETERS;
    }

    dbus_error_init(&error);

    msgQuery = dbus_message_new_method_call(
                           SEC_WELL_KNOWN_NAME,
                           SEC_SST_OBJECT_PATH,
                           SEC_SST_INTERFACE_NAME,
                           KC_DECRYPT_DATA);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        return KC_ERROR_GENERIC;
    }

    file_size = strlen(file_path) + 1;
    total_size = *data_len + key_len + file_size;

    KC_SHM_CREATE(total_size, shm_id);
    if (shm_id < 0) {
        log_e(TAG, "shm create failed errno: %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean1;
    }

    KC_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        log_e(TAG, "shm mmap failed errno %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean2;
    }
    memcpy(shm_buf, file_path, file_size);
    tmp_buf = shm_buf + file_size;
    memcpy(tmp_buf, key, key_len);
    tmp_buf += key_len;
    memset(data, 0, *data_len);

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, &key_len,
                             DBUS_TYPE_INT32, data_len,
                             DBUS_TYPE_INVALID);

    do {
        pthread_mutex_lock(&mutex);
        if (!connection) {
            pthread_mutex_unlock(&mutex);
            log_e(TAG, "please first call kc_init\n");
            result = KC_ERROR_GENERIC;
            break;
        }
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KC_ERROR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, data_len, DBUS_TYPE_INVALID);

        if (result == 0) {
            memcpy(data, tmp_buf, *data_len);
        } else if (result == KC_ERROR_SHORT_BUFFER) {
            log_e(TAG, "short buffer need %d\n", *data_len);
        }

        dbus_message_unref(msgReply);
    } while(0);

    KC_SHM_MUNMAP(shm_buf);
clean2:
    KC_SHM_DESTROY(shm_id);
clean1:
    dbus_message_unref(msgQuery);

    return result;
}

uint32_t kc_set_proc_domain_name(const char *domain_name)
{
    uint32_t domain_name_len = strlen(domain_name);
    if (domain_name_len > MAX_DOMAIN_NAME_LEN) {
        log_e(TAG, "too long domain name length\n");
        return KC_ERROR_BAD_PARAMETERS;
    }

    pthread_mutex_lock(&domain_mutex);
    if (strlen(proc_domain_name)) {
        log_e(TAG, "the process has already set domain\n");
        pthread_mutex_unlock(&domain_mutex);
        return KC_ERROR_ACCESS_DENIED;
    }
    memcpy(proc_domain_name, domain_name, domain_name_len);
    proc_domain_name[domain_name_len] = 0;
    pthread_mutex_unlock(&domain_mutex);

    return KC_SUCCESS;
}


uint32_t kc_add_global_item(const char *key_name, const uint8_t *key_sec, uint32_t key_sec_len, kc_key_type_t key_type)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    int result = 0;
    char name[FILENAME_MAX + 1];
    int shm_id = 0;
    void *buf = NULL;
    int total_size = 0;
    size_t name_size = 0;
    size_t key_size = 0;
    size_t secret_size = 0;
    int len = 0;

    if (!key_name || !key_sec || !key_sec_len ||
        key_type > KEY_CHAIN_USERDATA) {
        log_e(TAG, "bad null params\n");
        return KC_ERROR_BAD_PARAMETERS;
    }

    dbus_error_init(&error);
    msgQuery = dbus_message_new_method_call(
                           SEC_WELL_KNOWN_NAME,
                           SEC_SST_OBJECT_PATH,
                           SEC_SST_INTERFACE_NAME,
                           KC_ADD_GLOBAL_ITEM);

    //get the process name
    memset(name, 0, FILENAME_MAX + 1);
    len = readlink("/proc/self/exe", name, FILENAME_MAX);
    if (len <= 0) {
        log_e(TAG, "readlink fail\n");
        result = KC_ERROR_GENERIC;
        goto clean;
    }
    name_size = strlen(name) + 1;
    key_size = strlen(key_name) + 1;
    secret_size = key_sec_len;
    total_size = name_size + key_size + secret_size;

    KC_SHM_CREATE(total_size, shm_id);
    if (shm_id < 0) {
        log_e(TAG, "shm create failed errno: %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean;
    }
    KC_SHM_MMAP(shm_id, buf);
    if (buf == NULL) {
        log_e(TAG, "shm mmap failed\n");
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean1;
    }
    memcpy(buf, name, name_size);
    memcpy(buf + name_size, key_name, key_size);
    memcpy(buf + name_size + key_size, key_sec, secret_size);

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, &key_type,
                             DBUS_TYPE_INT32, &secret_size,
                             DBUS_TYPE_INVALID);
    do {
        pthread_mutex_lock(&mutex);
        if (!connection) {
            pthread_mutex_unlock(&mutex);
            log_e(TAG, "please first call kc_init\n");
            result = KC_ERROR_GENERIC;
            break;
        }
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            break;
        }

        dbus_message_get_args(msgReply, &error, DBUS_TYPE_INT32, &result, DBUS_TYPE_INVALID);

        dbus_message_unref(msgReply);
    } while(0);

    KC_SHM_MUNMAP(buf);
clean1:
    KC_SHM_DESTROY(shm_id);
clean:
    dbus_message_unref(msgQuery);

    return result;
}

uint32_t kc_get_global_item(const char *key_name, const uint8_t *key_sec, uint32_t *key_sec_len, kc_key_type_t *key_type) 
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    int result = 0;
    char name[FILENAME_MAX+1];
    int shm_id = 0;
    void *in_buf = NULL;
    int total_size = 0;
    int out_len = 0;
    size_t name_size = 0;
    size_t key_size = 0;
    int len = 0;

    if (!key_name || (!key_sec && *key_sec_len)) {
        log_e(TAG, "bad null params\n");
        return KC_ERROR_BAD_PARAMETERS;
    }

    dbus_error_init(&error);

    msgQuery = dbus_message_new_method_call(
                           SEC_WELL_KNOWN_NAME,
                           SEC_SST_OBJECT_PATH,
                           SEC_SST_INTERFACE_NAME,
                           KC_GET_GLOBAL_ITEM);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        return KC_ERROR_GENERIC;
    }

    memset(name, 0, FILENAME_MAX+1);
    len = readlink("/proc/self/exe", name, FILENAME_MAX);
    if (len <= 0) {
        log_e(TAG, "readlink fail\n");
        result = KC_ERROR_GENERIC;
        goto clean1;
    }

    name_size = len + 1;
    key_size = strlen(key_name) + 1;
    total_size = name_size + key_size + *key_sec_len;

    KC_SHM_CREATE(total_size, shm_id);
    if (shm_id < 0) {
        log_e(TAG, "shm create failed errno: %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean1;
    }

    KC_SHM_MMAP(shm_id, in_buf);
    if (in_buf == NULL) {
        log_e(TAG, "shm mmap failed errno %d\n", errno);
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean2;
    }
    memcpy(in_buf, name, name_size);
    memcpy(in_buf + name_size, key_name, key_size);
    memset(key_sec, 0, *key_sec_len);

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, key_sec_len,
                             DBUS_TYPE_INVALID);

    do {
        pthread_mutex_lock(&mutex);
        if (!connection) {
            pthread_mutex_unlock(&mutex);
            log_e(TAG, "please first call kc_init\n");
            result = KC_ERROR_GENERIC;
            break;
        }
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, &out_len,
                DBUS_TYPE_INT32, key_type,
                DBUS_TYPE_INVALID);
        if (result == 0) {
            memcpy(key_sec, in_buf + name_size + key_size, out_len);
            *key_sec_len = out_len;
        } else if (result == KC_ERROR_SHORT_BUFFER) {
            log_e(TAG, "short buffer %d : %d\n", *key_sec_len, out_len);
            *key_sec_len = out_len;
        }

        dbus_message_unref(msgReply);
    } while(0);

    KC_SHM_MUNMAP(in_buf);
clean2:
    KC_SHM_DESTROY(shm_id);
clean1:
    dbus_message_unref(msgQuery);

    return result;
}

