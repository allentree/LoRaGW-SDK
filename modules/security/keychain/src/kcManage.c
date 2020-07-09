#include <stdio.h>
#include <stdint.h>
#include <dbus/dbus.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include "sst.h"
#include "ali_crypto.h"
#include "tfs_log.h"
#include "kc_private.h"
#include "utils.h"
#include "sec_introspect.h"
#include "keychain.h"

#define MAX_FILE_NAME 255

#define SEND_ERR_REPLY(connection, request, str) do { \
    DBusMessage *reply = dbus_message_new_error(request, DBUS_ERROR_FAILED, str); \
    dbus_connection_send(connection, reply, NULL); \
    dbus_message_unref(reply); \
} while(0); \

static DBusHandlerResult message_handler(DBusConnection *connection, DBusMessage *message, void *user_data);
static uint32_t get_file_name(const char *service_name, const char *domain_name, const char *key, char **file_name);

#define GLOBAL_DATA_ACCESS_INVALID 0x0UL
#define GLOBAL_DATA_ACCESS_READ 0x1UL
#define GLOBAL_DATA_ACCESS_WRITE 0x2UL

typedef struct{
    const char * sev_name;
    unsigned int access;
}global_data_server_map_st;

global_data_server_map_st global_access[] = {
    {
        "mqtt",
        GLOBAL_DATA_ACCESS_READ|GLOBAL_DATA_ACCESS_WRITE,
    },
    {
        "update-deamon",
        GLOBAL_DATA_ACCESS_READ|GLOBAL_DATA_ACCESS_WRITE,
    },
    {
        "sec_sst_test_basic",
        GLOBAL_DATA_ACCESS_READ|GLOBAL_DATA_ACCESS_WRITE,
    },
    {
        "sec_sst_test",
        GLOBAL_DATA_ACCESS_READ|GLOBAL_DATA_ACCESS_WRITE,
    },
    {
        "loraserver",
        GLOBAL_DATA_ACCESS_READ|GLOBAL_DATA_ACCESS_WRITE,
    },
    {
        "lora-app-server",
        GLOBAL_DATA_ACCESS_READ|GLOBAL_DATA_ACCESS_WRITE,
    },
    {
        "loraconfig",
        GLOBAL_DATA_ACCESS_READ|GLOBAL_DATA_ACCESS_WRITE,
    }
    //todo : add other process
};
static int create_global_data_path();

static int check_global_service_legality(const char *sev_name);

static int check_sst_ready();

#define LORA_GLOBAL_DATA_PATH "/lora/gateway/global/data/path"
#define LORA_GLOBAL_DATA_FAKE1 "/lora/gateway/global/fake1/path"
#define LORA_GLOBAL_DATA_FAKE2 "/lora/gateway/global/fake2/path"

const char *sst_path = "/var/.sst/";
static char file_path[FILENAME_MAX + 1];
static char global_path[FILENAME_MAX + 1] = { 0 };

static uint32_t sst_to_kc_ret(uint32_t sst_ret)
{
    switch(sst_ret) {
        case SST_SUCCESS:
            return KC_SUCCESS;
        case SST_ERROR_ACCESS_DENIED:
            return KC_ERROR_ACCESS_DENIED;
        case SST_ERROR_ITEM_NOT_FOUND:
            return KC_ERROR_ITEM_NOT_FOUND;
        case SST_ERROR_BAD_PARAMETERS:
            return KC_ERROR_BAD_PARAMETERS;
        case SST_ERROR_OUT_OF_MEMORY:
            return KC_ERROR_OUT_OF_MEMORY;
        case SST_ERROR_STORAGE_NO_SPACE:
            return KC_ERROR_STORAGE_NO_SPACE;
        case SST_ERROR_STORAGE_NOT_AVAILABLE:
            return KC_ERROR_STORAGE_NOT_AVAILABLE;
        case SST_ERROR_OVERFLOW:
            return KC_ERROR_OVERFLOW;
        case SST_ERROR_SHORT_BUFFER:
            return KC_ERROR_SHORT_BUFFER;
        case SST_ERROR_GENERIC:
        case SST_ERROR_ACCESS_CONFLICT:
        case SST_ERROR_BUSY:
        default:
            return KC_ERROR_GENERIC;
    }
}

static uint32_t _errno_to_kc_ret(int linux_errno)
{
    switch(linux_errno) {
        case 1:
        case 13:
            return KC_ERROR_ACCESS_DENIED;
        case 2:
            return KC_ERROR_BAD_PARAMETERS;
        case 12:
            return KC_ERROR_OUT_OF_MEMORY;
        default:
            return KC_ERROR_GENERIC;
    }
}

uint32_t sec_sst_init(DBusConnection *connection) {
    dbus_bool_t ret;
    uint32_t sst_ret = 0;
    DBusObjectPathVTable vtable;
    DBusError error;

    sst_ret = check_sst_ready();
    if (sst_ret != 0) {
        log_e(TAG, "sst is not ready, please deploy sst\n");
        return -1;
    }

    log_d(TAG, "sst is ready...\n");

    vtable.message_function = message_handler;
    vtable.unregister_function = NULL;

    dbus_error_init(&error);
    dbus_connection_try_register_object_path(connection,
            SEC_SST_OBJECT_PATH,
            &vtable,
            NULL,
            &error);
    if (dbus_error_is_set(&error)) {
        log_e(TAG, "dbus_connection_try_register_object_path dbus error (%s)\n", error.message);
        dbus_error_free(&error);
        return -1;
    }

    sst_ret = create_global_data_path();
    if(sst_ret != KC_SUCCESS) {
        log_e(TAG, "create global data path error!!!");
        return -1;
    }
    return 0;
}

static uint32_t _create_parent_folder(char *file_name)
{
    uint32_t idx = strlen((char *)file_name);
    DIR *dir;
    int32_t res;

    while (--idx) {
        if ('/' == file_name[idx]) {
            file_name[idx] = '\0';
            break;
        }
    }

    dir = opendir((char *)file_name);
    if (NULL == dir) {
        /* no parent folder found, then create it */
        int linux_errno = errno;
        res = mkdir((char *)file_name, S_IRWXU);
        if (res < 0) {
            file_name[idx] = '/';
            log_e(TAG, "failed to mkdir, %d\n", linux_errno);
            return _errno_to_kc_ret(linux_errno);
        }
    } else {
        (void)closedir(dir);
    }

    file_name[idx] = '/';

    return 0;
}

//flag 0 : for proc item
//flag 1 : for domain item need to delete parent folder
static uint32_t _destroy_parent_folder(char *file_name, uint32_t *flag)
{
    uint32_t idx = strlen(file_name);
    DIR *dir = NULL;
    struct dirent *d;
    uint32_t n = 0;

    *flag = 0;
    while (--idx) {
        if ('/' == file_name[idx]) {
            file_name[idx] = '\0';
            break;
        }
    }

    if (access((char *)file_name, F_OK) < 0) {
        log_e(TAG, "folder %s does not exist\n", file_name);
        return KC_SUCCESS;
    }

    dir = opendir((char *)file_name);
    while ((d = readdir(dir)) != NULL) {
        if(++n > 2) {
            break;
        }
    }
    closedir(dir);

    /* "." and ".." left */
    if (n <= 2) {
        int32_t ret;
        log_d(TAG, "folder %s is empty, to be removed\n", file_name);
        ret = rmdir((char *)file_name);
        if (-1 == ret) {
            file_name[idx] = '/';
            log_e(TAG, "failed to rmdir, %d\n", errno);
            return KC_ERROR_GENERIC;
        }

        *flag = 1;
    }

    return 0;
}
void _sec_store_global(DBusConnection *connection, DBusMessage *request){
    DBusMessage *reply;
    DBusError error;
    char *sev_name = NULL; // service 's name
    char *key = NULL;
    uint8_t *secret = NULL;
    uint32_t secret_len = 0;
    int result = -1;
    uint32_t sst_ret;
    int shm_id = -1;
    char *store_args;
    kc_key_type_t key_type;

    log_d(TAG, "sec_store_global\n");

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &key_type,
                          DBUS_TYPE_INT32, &secret_len,
                          DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get args failed");
        return;
    }

    KC_SHM_MMAP(shm_id, store_args);
    if (store_args == NULL) {
        log_e(TAG, "sst daemon map sharedmemory failed\n");
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean;
    }
    sev_name = store_args;
    key = sev_name + strlen(sev_name) + 1;
    secret = key + strlen(key) + 1;

    if (strcmp(sev_name, "") == 0 || strcmp(key, "") == 0) {
        KC_SHM_MUNMAP(store_args);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    if(!(check_global_service_legality(sev_name) & GLOBAL_DATA_ACCESS_WRITE)) {
        log_e(TAG, "service legality!!!");
        result = KC_ERROR_ACCESS_DENIED;
        goto out;
    }
    memset(file_path, 0, FILENAME_MAX + 1);
    if(strlen(global_path) + strlen(key) + 1 > FILENAME_MAX) {
        log_e(TAG, "file_name too long for system\n");
        result = KC_ERROR_OVERFLOW;
    }
    else {
        sprintf(file_path, "%s/%s", global_path, key);
        sst_ret = sst_add_item(file_path, secret, secret_len, key_type, 1);
        result = sst_to_kc_ret(sst_ret);
    }

out:
    KC_SHM_MUNMAP(store_args);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &result,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);
}

void _sec_store(DBusConnection *connection, DBusMessage *request){
    DBusMessage *reply;
    DBusError error;
    char *sev_name = NULL; // service 's name
    char *key = NULL;
    uint8_t *secret = NULL;
    uint32_t secret_len = 0;
    int result = -1;
    uint32_t sst_ret;
    char *file_name = NULL;
    int shm_id = -1;
    char *store_args;
    char *folder_path;
    char real_path[FILENAME_MAX + 1] = { 0 };
    char *last_path = NULL;
    char *p = NULL;
    int i = 0;
    uint8_t copy_len = 0;
    kc_key_type_t key_type;
    char *domain_name = NULL;
    uint32_t domain_name_len = 0;

    log_d(TAG, "sec_store\n");

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &key_type,
                          DBUS_TYPE_INT32, &secret_len,
                          DBUS_TYPE_INT32, &domain_name_len,
                          DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get args failed");
        return;
    }

    KC_SHM_MMAP(shm_id, store_args);
    if (store_args == NULL) {
        log_e(TAG, "sst daemon map sharedmemory failed\n");
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean;
    }
    sev_name = store_args;
    key = sev_name + strlen(sev_name) + 1;
    secret = key + strlen(key) + 1;
    if (domain_name_len) {
        domain_name = secret + secret_len;
    }

    if (strcmp(sev_name, "") == 0 || strcmp(key, "") == 0) {
        KC_SHM_MUNMAP(store_args);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    sst_ret = get_file_name(sev_name, domain_name, key, &file_name);
    if(sst_ret == KC_SUCCESS) {
        memset(file_path, 0, FILENAME_MAX + 1);
        if( strlen(sst_path) + strlen(file_name) + 1 > FILENAME_MAX) {
            log_e(TAG, "file_name too long for system\n");
            result = KC_ERROR_OVERFLOW;
        } else {
            strncpy(file_path, sst_path, strlen(sst_path));
            strncpy(file_path + strlen(sst_path), file_name, strlen(file_name));
            last_path = strrchr(file_path, '/');
            p = file_path;
            while (p != last_path) {
                real_path[i] = file_path[i];
                p++;
                i++;
            }

            if (*real_path == 0) {
                result = KC_ERROR_GENERIC;
                free(file_name);
                goto out;
            }

            if (domain_name_len) {
                result = _create_parent_folder(real_path);
                if (result) {
                    log_e(TAG, "create parent filder failed\n");
                    free(file_name);
                    goto out;
                }
            }

            if (access(real_path, 7) != 0 ) {
                if (mkdir(real_path, S_IRWXU) != 0) {
                    int linux_errno = errno;
                    log_e(TAG, "create directory %s fail, errno %d\n", file_name, linux_errno);
                    result = _errno_to_kc_ret(linux_errno);
                    free(file_name);
                    goto out;
                }
            }
            sst_ret = sst_add_item(file_path, secret, secret_len, key_type, 1);
            result = sst_to_kc_ret(sst_ret);
        }
        free(file_name);
    }

out:
    KC_SHM_MUNMAP(store_args);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &result,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);
}

void _sec_get_global(DBusConnection *connection, DBusMessage *request) {
    DBusMessage *reply;
    DBusError error;
    char *sev_name = NULL; // service 's name
    char *key = NULL;
    char *secret = NULL;
    int result = -1;
    uint32_t sst_ret = 0;
    int input_size = 0;
    uint32_t secret_len = 0;
    char *get_args;
    int shm_id = 0;
    kc_key_type_t key_type;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &input_size,
                          DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get args failed");
        return;
    }

    KC_SHM_MMAP(shm_id, get_args);
    if (get_args == NULL) {
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean;
    }
    sev_name = get_args;
    key = sev_name + strlen(sev_name) + 1;
    secret = key + strlen(key) + 1;

    if (strcmp(sev_name, "") == 0 || strcmp(key, "") == 0) {
        KC_SHM_MUNMAP(get_args);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }
    if(!(check_global_service_legality(sev_name) & GLOBAL_DATA_ACCESS_READ)) {
        log_e(TAG, "service legality!!!");
        result = KC_ERROR_ACCESS_DENIED;
        goto out;
    }

    do {
        memset(file_path, 0, FILENAME_MAX + 1);
        if(strlen(global_path) + strlen(key) + 1 > FILENAME_MAX) {
            log_e(TAG, "file_name too long for system\n");
            sst_ret = KC_ERROR_OVERFLOW;
            break;
        }
        sprintf(file_path, "%s/%s", global_path, key);

        sst_ret = sst_get_item(file_path, NULL, &secret_len, &key_type);
        if (SST_ERROR_SHORT_BUFFER != sst_ret) {
            log_e(TAG, "sst_get_file_size fail, error code is %X\n", sst_ret);
            sst_ret = sst_to_kc_ret(sst_ret);
            break;
        }

        if (input_size < secret_len) {
            log_e(TAG, "short buffer %d : %d\n", input_size, secret_len);
            sst_ret = KC_ERROR_SHORT_BUFFER;
            break;
        }

        sst_ret = sst_get_item(file_path, secret, &secret_len, &key_type);
        if (sst_ret != SST_SUCCESS) {
            log_e(TAG, "sst_get_file fail.\n");
            sst_ret = sst_to_kc_ret(sst_ret);
            break;
        }
    } while(0);
out:
    //unmap shm for input arg
    KC_SHM_MUNMAP(get_args);
clean:
    result = sst_ret;
    reply = dbus_message_new_method_return(request);

    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &result,
                             DBUS_TYPE_INT32, &secret_len,
                             DBUS_TYPE_INT32, &key_type,
                             DBUS_TYPE_INVALID);

    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);
}

void _sec_get(DBusConnection *connection, DBusMessage *request) {
    DBusMessage *reply;
    DBusError error;
    char *sev_name = NULL; // service 's name
    char *key = NULL;
    char *secret = NULL;
    int result = -1;
    uint32_t sst_ret = 0;
    int input_size = 0;
    uint32_t secret_len = 0;
    char *file_name = NULL;
    char *get_args;
    int shm_id = 0;
    uint8_t copy_len = 0;
    kc_key_type_t key_type;
    char *domain_name = NULL;
    uint32_t domain_name_len = 0;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &input_size,
                          DBUS_TYPE_INT32, &domain_name_len,
                          DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get args failed");
        return;
    }

    KC_SHM_MMAP(shm_id, get_args);
    if (get_args == NULL) {
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean;
    }
    sev_name = get_args;
    key = sev_name + strlen(sev_name) + 1;
    secret = key + strlen(key) + 1;

    if (domain_name_len) {
        domain_name = secret + input_size;
    }

    if (strcmp(sev_name, "") == 0 || strcmp(key, "") == 0) {
        KC_SHM_MUNMAP(get_args);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    do {
        sst_ret = get_file_name(sev_name, domain_name, key, &file_name);
        if (sst_ret) {
            log_e(TAG, "file_name is NULL\n");
            break;
        }

        memset(file_path, 0, FILENAME_MAX + 1);
        if(strlen(sst_path) + strlen(file_name) > FILENAME_MAX) {
            log_e(TAG, "file_name too long for system\n");
            sst_ret = KC_ERROR_OVERFLOW;
            break;
        }

        strncpy(file_path, sst_path, strlen(sst_path));
        strncpy(file_path + strlen(sst_path), file_name, strlen(file_name));

        //log_d(TAG, "file name is %s, size %d\n", file_name, (int)strlen(file_name));
        sst_ret = sst_get_item(file_path, NULL, &secret_len, &key_type);
        if (SST_ERROR_SHORT_BUFFER != sst_ret) {
            log_e(TAG, "sst_get_file_size fail, error code is %X\n", sst_ret);
            sst_ret = sst_to_kc_ret(sst_ret);
            break;
        }

        if (input_size < secret_len) {
            log_e(TAG, "short buffer %d : %d\n", input_size, secret_len);
            sst_ret = KC_ERROR_SHORT_BUFFER;
            break;
        }

        sst_ret = sst_get_item(file_path, secret, &secret_len, &key_type);
        if (sst_ret != SST_SUCCESS) {
            log_e(TAG, "sst_get_file fail.\n");
            sst_ret = sst_to_kc_ret(sst_ret);
            break;
        }
    } while(0);

    //unmap shm for input arg
    KC_SHM_MUNMAP(get_args);
clean:
    result = sst_ret;
    reply = dbus_message_new_method_return(request);

    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &result,
                             DBUS_TYPE_INT32, &secret_len,
                             DBUS_TYPE_INT32, &key_type,
                             DBUS_TYPE_INVALID);

    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

    if (file_name != NULL) {
        free(file_name);
        file_name = NULL;
    }
}

void _kc_delete_global_item(DBusConnection *connection, DBusMessage *request) {
    DBusMessage *reply;
    DBusError error;
    char *sev_name = NULL; // service 's name
    char *key = NULL;
    int result = -1;
    uint32_t sst_ret = 0;
    char *get_args;
    int shm_id = 0;

    uint32_t flag = 0;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get args failed");
        return;
    }

    KC_SHM_MMAP(shm_id, get_args);
    if (get_args == NULL) {
        sst_ret = KC_ERROR_OUT_OF_MEMORY;
        goto clean;
    }
    sev_name = get_args;
    key = sev_name + strlen(sev_name) + 1;

    if (strcmp(sev_name, "") == 0 || strcmp(key, "") == 0) {
        KC_SHM_MUNMAP(get_args);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    if(!(check_global_service_legality(sev_name) & GLOBAL_DATA_ACCESS_WRITE)) {
        log_e(TAG, "service legality!!!");
        result = KC_ERROR_ACCESS_DENIED;
        goto out;
    }

    do {

        memset(file_path, 0, FILENAME_MAX + 1);
        if(strlen(global_path) + strlen(key) + 1 > FILENAME_MAX) {
            log_e(TAG, "file_name too long for system\n");
            sst_ret = KC_ERROR_OVERFLOW;
            break;
        }
        sprintf(file_path, "%s/%s", global_path, key);

        sst_ret = sst_delete_item(file_path);
        if (sst_ret != SST_SUCCESS) {
            log_e(TAG, "sst_get_file fail.\n");
            sst_ret = sst_to_kc_ret(sst_ret);
            break;
        }


    } while(0);
out:
    //unmap shm for input arg
    KC_SHM_MUNMAP(get_args);
clean:
    result = sst_ret;
    reply = dbus_message_new_method_return(request);

    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &result,
                             DBUS_TYPE_INVALID);

    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

}

void _kc_delete_item(DBusConnection *connection, DBusMessage *request) {
    DBusMessage *reply;
    DBusError error;
    char *sev_name = NULL; // service 's name
    char *key = NULL;
    int result = -1;
    uint32_t sst_ret = 0;
    char *file_name = NULL;
    char *get_args;
    int shm_id = 0;
    char *domain_name = NULL;
    uint32_t domain_name_len = 0;
    uint32_t flag = 0;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &domain_name_len,
                          DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get args failed");
        return;
    }

    KC_SHM_MMAP(shm_id, get_args);
    if (get_args == NULL) {
        sst_ret = KC_ERROR_OUT_OF_MEMORY;
        goto clean;
    }
    sev_name = get_args;
    key = sev_name + strlen(sev_name) + 1;

    if (domain_name_len) {
        domain_name = key + strlen(key) + 1;
    }

    if (strcmp(sev_name, "") == 0 || strcmp(key, "") == 0) {
        KC_SHM_MUNMAP(get_args);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    do {
        sst_ret = get_file_name(sev_name, domain_name, key, &file_name);
        if (sst_ret) {
            log_e(TAG, "file_name is NULL\n");
            break;
        }

        memset(file_path, 0, FILENAME_MAX + 1);
        if(strlen(sst_path) + strlen(file_name) > FILENAME_MAX) {
            log_e(TAG, "file_name too long for system\n");
            sst_ret = KC_ERROR_OVERFLOW;
            break;
        }

        strncpy(file_path, sst_path, strlen(sst_path));
        strncpy(file_path + strlen(sst_path), file_name, strlen(file_name));

        sst_ret = sst_delete_item(file_path);
        if (sst_ret != SST_SUCCESS) {
            log_e(TAG, "sst_get_file fail.\n");
            sst_ret = sst_to_kc_ret(sst_ret);
            break;
        }

       sst_ret =  _destroy_parent_folder(file_path, &flag);
       if (sst_ret) {
           log_e(TAG, "sst_get_file fail.\n");
           break;
       }

       //need to delete proc folder for domain item
       if (domain_name_len && flag) {
           sst_ret =  _destroy_parent_folder(file_path, &flag);
           if (sst_ret) {
               log_e(TAG, "destroy parent folder %s fail.\n", file_path);
               break;
           }
       }
    } while(0);

    //unmap shm for input arg
    KC_SHM_MUNMAP(get_args);
clean:
    result = sst_ret;
    reply = dbus_message_new_method_return(request);

    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &result,
                             DBUS_TYPE_INVALID);

    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

    if (file_name != NULL) {
        free(file_name);
        file_name = NULL;
    }
}

void _kc_encrypt_data(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    char *file_path = NULL;
    uint32_t key_len = 0;
    uint8_t *key = NULL;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    int result = -1;
    uint32_t sst_ret;
    char folder_path[MAX_FILE_NAME];
    char *folder_end = NULL;
    int i = 0;
    char *p = NULL;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &data_len,
                          DBUS_TYPE_INT32, &key_len,
                          DBUS_TYPE_INVALID);

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get args failed");
        return;
    }

    KC_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean1;
    }
    data = shm_buf;
    file_path = data + data_len;
    key = file_path + strlen(file_path) + 1;

    if (strcmp(file_path, "") == 0) {
        KC_SHM_MUNMAP(shm_buf);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    //check if file exist if not create it
    memset(folder_path, 0, MAX_FILE_NAME);
    folder_end = strrchr(file_path, '/');
    p = file_path;
    while (p != folder_end) {
        folder_path[i] = file_path[i];
        p++;
        i++;
    }

    if (access(folder_path, 7) != 0) {
        if (mkdir(folder_path, S_IRWXU) != 0) {
            int linux_errno = errno;
            log_e(TAG, "create folder fail, errno %d\n", linux_errno);
            result = _errno_to_kc_ret(linux_errno);
            goto clean;
        }
    }

    do {
        sst_ret = sst_encrypt_data(data, data_len, file_path, key, &key_len);
        if (SST_SUCCESS != sst_ret) {
            log_e(TAG, "sst_get_file_size fail, error code is %X\n", sst_ret);
            result = sst_to_kc_ret(sst_ret);
            break;
        }

        result = sst_to_kc_ret(sst_ret);
    } while(0);

clean:
    //unmap shm for input arg
    KC_SHM_MUNMAP(shm_buf);
clean1:
    reply = dbus_message_new_method_return(request);

    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &result,
                             DBUS_TYPE_INT32, &key_len,
                             DBUS_TYPE_INVALID);

    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);
}

void _kc_decrypt_data(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    char *file_path = NULL;
    uint32_t key_len = 0;
    char *key = NULL;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    int result = -1;
    uint32_t sst_ret;

    dbus_error_init(&error);
    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &key_len,
                          DBUS_TYPE_INT32, &data_len,
                          DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get args failed");
        return;
    }

    KC_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KC_ERROR_OUT_OF_MEMORY;
        goto clean;
    }
    file_path = shm_buf;
    key = file_path + strlen(file_path) + 1;
    data = key + key_len;
    memset(data, 0, data_len);

    if (strcmp(file_path, "") == 0) {
        KC_SHM_MUNMAP(shm_buf);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    do {
        sst_ret = sst_decrypt_data(file_path, key, key_len, data, &data_len);
        if (SST_SUCCESS != sst_ret) {
            log_e(TAG, "sst_get_file_size fail, error code is %X\n", sst_ret);
            result = sst_to_kc_ret(sst_ret);
            break;
        }
        result = sst_to_kc_ret(sst_ret);
    } while(0);

    //unmap shm for input arg
    KC_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);

    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &result,
                             DBUS_TYPE_INT32, &data_len,
                             DBUS_TYPE_INVALID);

    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);
}

static DBusHandlerResult message_handler(DBusConnection *connection,
        DBusMessage *message, void *user_data)
{
    int message_type = dbus_message_get_type(message);

    switch (message_type) {
        case DBUS_MESSAGE_TYPE_METHOD_CALL:
            if (dbus_message_is_method_call(message, SEC_SST_INTERFACE_NAME, KC_ADD_ITEM)) {
                _sec_store(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_SST_INTERFACE_NAME, KC_GET_ITEM)) {
                _sec_get(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_SST_INTERFACE_NAME, KC_DELETE_ITEM)) {
                _kc_delete_item(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_SST_INTERFACE_NAME, KC_DELETE_GLOBAL_ITEM)) {
                _kc_delete_global_item(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_SST_INTERFACE_NAME, KC_ENCRYPT_DATA)) {
                _kc_encrypt_data(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_SST_INTERFACE_NAME, KC_DECRYPT_DATA)) {
                _kc_decrypt_data(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if(dbus_message_is_method_call(message, SEC_SST_INTERFACE_NAME, KC_ADD_GLOBAL_ITEM)) {
                _sec_store_global(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if(dbus_message_is_method_call(message, SEC_SST_INTERFACE_NAME, KC_GET_GLOBAL_ITEM)) {
                _sec_get_global(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            }
            break;
        default:
            break;
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static uint32_t get_file_name(const char *service_name, const char *domain_name, const char *key, char **file_name) {
    uint8_t hash_dst[SHA256_HASH_SIZE];
    char hash_dst2[2 * SHA256_HASH_SIZE + 1];
    uint32_t ret = 0;
    ali_crypto_result alicrypto_ret;
    int check_ret = 0;
    int total_len = 2 * SHA256_HASH_SIZE + 1 + strlen(key) + 1; //'/', \0
    char *tmp = NULL;

    if (domain_name) {
        total_len += 2 * SHA256_HASH_SIZE + 1;
    }
/*
    log_d(TAG, "service_name is %s\n", service_name);
*/
    memset(hash_dst, 0, SHA256_HASH_SIZE);
    memset(hash_dst2, 0, 2 * SHA256_HASH_SIZE + 1);

    //service name : folder name
    alicrypto_ret = ali_hash_digest(SHA256, service_name, strlen(service_name), hash_dst);

    if (ALI_CRYPTO_SUCCESS != alicrypto_ret) {
        log_e(TAG, "alicrypto hash fail.\n");
        ret = KC_ERROR_GENERIC;
    } else {
       int i = 0;
        for (i = 0; i < SHA256_HASH_SIZE; i ++) {
            sprintf(hash_dst2 + 2 * i, "%02X", hash_dst[i]);
        }
        //log_d(TAG, "hash is %s\n", hash_dst2);
        *file_name = (char *)malloc(total_len);
        if (*file_name == NULL) {
            log_e(TAG, "file_name malloc fail.\n");
            return KC_ERROR_OUT_OF_MEMORY;
        } else {
            memset(*file_name, 0, total_len);
            strncpy(*file_name, hash_dst2, strlen(hash_dst2));
        }

        ((uint8_t *)(*file_name))[2 * SHA256_HASH_SIZE] = '/';
        if (domain_name) {
            alicrypto_ret = ali_hash_digest(SHA256, domain_name, strlen(domain_name), hash_dst);
            if (alicrypto_ret) {
                log_e(TAG, "alicrypto hash failed\n");
                free(*file_name);
                *file_name = NULL;
                return KC_ERROR_GENERIC;
            }
            for (i = 0; i < SHA256_HASH_SIZE; i ++) {
                sprintf(hash_dst2 + 2 * i, "%02X", hash_dst[i]);
            }
            tmp = *file_name;
            tmp += 2 * SHA256_HASH_SIZE + 1;
            strncpy(tmp, hash_dst2, 2 * SHA256_HASH_SIZE);
            tmp += 2 * SHA256_HASH_SIZE;
            *tmp = '/';
            strncpy(tmp + 1, key, strlen(key));
        } else {
            strncpy(*file_name + 2 * SHA256_HASH_SIZE + 1, key, strlen(key));
        }
    }

    return ret;
}

static int check_sst_ready() {
#if NO_RSVD_PART_SUPPORT
    char *km_file;
    char *km_bak_file;
    char *km_sig_file;
    char *km_bak_sig_file;

    km_file = get_sec_sys_name();
    km_bak_file = get_sec_sys_bak_name();
    km_sig_file = get_sec_sys_sig_name();
    km_bak_sig_file = get_sec_sys_bak_sig_name();

    if (check_file_sig(km_file, km_sig_file) != 0
        || check_file_sig(km_bak_file, km_bak_sig_file) != 0
        || check_file_same(km_sig_file, km_bak_sig_file) != 0) {
        return -1;
    }
#endif /* NO_RSVD_PART_SUPPORT */

    return 0;
}


int create_global_data_path()
{
    uint32_t sst_ret;
    char *file_name = NULL;
    char *last_path = NULL;
    char *p = NULL;
    int i = 0;
    uint32_t result = KC_SUCCESS;
    

    sst_ret = get_file_name(LORA_GLOBAL_DATA_PATH, NULL, "", &file_name);
    if(sst_ret != KC_SUCCESS) {
        log_e(TAG,"get global data path failed!!!");
        return sst_ret;
    }
    memset(file_path, 0, FILENAME_MAX + 1);
    if( strlen(sst_path) + strlen(file_name) + 1 > FILENAME_MAX) {
        log_e(TAG, "file_name too long for system\n");
        result = KC_ERROR_OVERFLOW;
    } else {
        strncpy(file_path, sst_path, strlen(sst_path));
        strncpy(file_path + strlen(sst_path), file_name, strlen(file_name));
        last_path = strrchr(file_path, '/');
        p = file_path;
        while (p != last_path) {
            global_path[i] = file_path[i];
            p++;
            i++;
        }

        if (*global_path == 0) {
            result = KC_ERROR_GENERIC;
            free(file_name);
            goto out;
        }
        if (access(global_path, 7) != 0 ) {
            if (mkdir(global_path, S_IRWXU) != 0) {
                int linux_errno = errno;
                log_e(TAG, "create directory %s fail, errno %d\n", file_name, linux_errno);
                result = _errno_to_kc_ret(linux_errno);
                free(file_name);
                goto out;
            }
        }
    }
    free(file_name);
out: 
    return result;
}

int check_global_service_legality(const char *sev_name)
{
    int i = 0;
    int size = sizeof(global_access)/sizeof(global_data_server_map_st);
    const char * process_name = NULL;
    process_name = strrchr(sev_name, '/');
    if(!process_name) {
        log_e(TAG, "server name error!!!");
        return GLOBAL_DATA_ACCESS_INVALID;
    }
    
    process_name++;

    if(strlen(process_name) == 0) {
        log_e(TAG,"server name error!!!");
        return GLOBAL_DATA_ACCESS_INVALID;
    }
    for(i = 0 ; i < size; i++ ) {
        if(strcmp(process_name, global_access[i].sev_name) == 0) {
            return global_access[i].access;
        }
    }

    return GLOBAL_DATA_ACCESS_INVALID;
}
