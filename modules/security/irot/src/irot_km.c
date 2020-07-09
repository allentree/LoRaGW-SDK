#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dbus/dbus.h>
#include <pthread.h>
#include "tfs_log.h"
#include "irot_private.h"
#include "km.h"

static DBusConnection *connection = NULL;
static pthread_mutex_t mutex;

typedef struct _irot_op_handle_t {
    km_key_type key_type;
    km_op_handle_t km_op_handle;
} irot_op_handle_t;

uint32_t irot_init()
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
    if (ret == FALSE) { //ret != TURE
        goto clean;
    }
    pthread_mutex_unlock(&mutex);

    return KM_SUCCESS;

clean:
    pthread_mutex_unlock(&mutex);
    pthread_mutex_destroy(&mutex);

    return KM_ERR_GENERIC;
}

void irot_destroy()
{
    pthread_mutex_lock(&mutex);
    if (connection) {
        dbus_connection_close(connection);
        connection = NULL;
    }
    pthread_mutex_unlock(&mutex);

    pthread_mutex_destroy(&mutex);
}

uint32_t km_generate_key(const char *name, const uint32_t name_len,
                     km_key_type key_type, void *arg)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t arg_len = 0;
    uint32_t total_len = 0;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint8_t *tmp_buf = NULL;
    uint32_t result = 0;

    switch(key_type) {
        case KM_AES:
        case KM_HMAC: {
            arg_len = sizeof(km_sym_gen_param);
            break;
        }
        default:
            log_d(TAG, "not support key type %d\n", key_type);
            return KM_ERR_NOT_SUPPORTED;
    }

    total_len = name_len + arg_len + 2 * sizeof(uint32_t);
    IROT_SHM_CREATE(total_len, shm_id);
    IROT_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    //name_len | name | arg_len | arg
    memset(shm_buf, 0, total_len);
    UINT_TO_BIN(name_len, shm_buf);
    tmp_buf = shm_buf + sizeof(uint32_t);
    memcpy(tmp_buf, name, name_len);
    tmp_buf += name_len;
    UINT_TO_BIN(arg_len, tmp_buf);
    tmp_buf += sizeof(uint32_t);
    memcpy(tmp_buf, arg, arg_len);

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_GEN_KEY);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, &key_type,
                             DBUS_TYPE_INVALID);

    do {
        dbus_error_init(&error);
        pthread_mutex_lock(&mutex);
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error, DBUS_TYPE_INT32, &result, DBUS_TYPE_INVALID);
        dbus_error_parse(error);

        dbus_message_unref(msgReply);
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_import_key(const char *name, const uint32_t name_len, km_format_t format,
                   const km_key_data_t *key_data, const uint32_t key_data_len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t total_len = 0;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint8_t *tmp_buf = NULL;
    uint32_t result = 0;
    km_key_data_t *km_key_data = (km_key_data_t *)key_data;
    km_key_type key_type;

    if (!name || !name_len || !key_data) {
        return KM_ERR_BAD_PARAMS;
    }

    total_len = name_len + UINT32_LEN;
    key_type = km_key_data->type;

    switch (key_type) {
        case KM_RSA: {
            km_rsa_key_t *rsa_key = &(km_key_data->rsa_key);
            uint32_t n_len = rsa_key->n_len;
            uint32_t e_len = rsa_key->e_len;
            uint32_t d_len = rsa_key->d_len;
            uint32_t p_len = rsa_key->p_len;
            uint32_t q_len = rsa_key->q_len;
            uint32_t dp_len = rsa_key->dp_len;
            uint32_t dq_len = rsa_key->dq_len;
            uint32_t iq_len = rsa_key->iq_len;

            total_len += 8 * UINT32_LEN + n_len + e_len + d_len +
                p_len + q_len + dp_len + dq_len + iq_len;
            IROT_SHM_CREATE(total_len, shm_id);
            IROT_SHM_MMAP(shm_id, shm_buf);
            if (shm_buf == NULL) {
                result = KM_ERR_OUT_OF_MEMORY;
                goto clean;
            }

            //name_len | name | rsa_key
            memset(shm_buf, 0, total_len);
            UINT_TO_BIN(name_len, shm_buf);
            tmp_buf = shm_buf + UINT32_LEN;
            memcpy(tmp_buf, name, name_len);
            tmp_buf += name_len;
            //n
            UINT_TO_BIN(n_len, tmp_buf);
            tmp_buf += UINT32_LEN;
            memcpy(tmp_buf, rsa_key->n, n_len);
            tmp_buf += n_len;
            //e
            UINT_TO_BIN(e_len, tmp_buf);
            tmp_buf += UINT32_LEN;
            memcpy(tmp_buf, rsa_key->e, e_len);
            tmp_buf += e_len;
            //d
            UINT_TO_BIN(d_len, tmp_buf);
            tmp_buf += UINT32_LEN;
            memcpy(tmp_buf, rsa_key->d, d_len);
            tmp_buf += d_len;
            //p
            UINT_TO_BIN(p_len, tmp_buf);
            tmp_buf += UINT32_LEN;
            if (p_len) {
                memcpy(tmp_buf, rsa_key->p, p_len);
                tmp_buf += p_len;
            }
            //q
            UINT_TO_BIN(q_len, tmp_buf);
            tmp_buf += UINT32_LEN;
            if (q_len) {
                memcpy(tmp_buf, rsa_key->q, q_len);
                tmp_buf += q_len;
            }
            //dp
            UINT_TO_BIN(dp_len, tmp_buf);
            tmp_buf += UINT32_LEN;
            if (dp_len) {
                memcpy(tmp_buf, rsa_key->dp, dp_len);
                tmp_buf += dp_len;
            }
            //dq
            UINT_TO_BIN(dq_len, tmp_buf);
            tmp_buf += UINT32_LEN;
            if (dq_len) {
                memcpy(tmp_buf, rsa_key->dq, dq_len);
                tmp_buf += dq_len;
            }
            //iq
            UINT_TO_BIN(iq_len, tmp_buf);
            tmp_buf += UINT32_LEN;
            if (iq_len) {
                memcpy(tmp_buf, rsa_key->iq, iq_len);
                tmp_buf += iq_len;
            }
            break;
        }
        case KM_AES:
        case KM_HMAC: {
            km_sym_key_t *sym_key = &(km_key_data->sym_key);
            uint32_t key_len = sym_key->key_bit >> 3;

            total_len += UINT32_LEN + key_len;
            IROT_SHM_CREATE(total_len, shm_id);
            IROT_SHM_MMAP(shm_id, shm_buf);
            if (shm_buf == NULL) {
                result = KM_ERR_OUT_OF_MEMORY;
                goto clean;
            }

            //name_len | name | key_bit | key
            memset(shm_buf, 0, total_len);
            UINT_TO_BIN(name_len, shm_buf);
            tmp_buf = shm_buf + UINT32_LEN;
            memcpy(tmp_buf, name, name_len);
            tmp_buf += name_len;
            UINT_TO_BIN(key_len, tmp_buf);
            memcpy(tmp_buf + UINT32_LEN, sym_key->key, key_len);

            break;
        }
        default: {
            log_e(TAG, "not support key type %d\n", key_type);
            return KM_ERR_GENERIC;
        }
    }

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_IM_KEY);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, &format,
                             DBUS_TYPE_INT32, &key_type,
                             DBUS_TYPE_INVALID);

    do {
        dbus_error_init(&error);
        pthread_mutex_lock(&mutex);
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result, DBUS_TYPE_INVALID);

        dbus_error_parse(error);
        dbus_message_unref(msgReply);
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_export_key(const char *name, const uint32_t name_len, km_format_t format,
                   uint8_t *export_data, uint32_t *export_data_size)
{
    log_e(TAG, "not support yet\n");

    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_mac(const char *name, const uint32_t name_len, km_sym_param *mac_params,
        const uint8_t *iv, const uint32_t iv_len, uint8_t *src, size_t src_len,
        uint8_t *mac, uint32_t *mac_len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t total_len = 0;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint8_t *tmp_buf = NULL;
    uint32_t result;

    if (!mac_len || (!mac && *mac_len)) {
        log_e(TAG, "bad params\n");
        return KM_ERR_BAD_PARAMS;
    }

    //name_len | name | mac_params | iv_len | iv | src_len | src | mac
    total_len = name_len + UINT32_LEN + sizeof(km_sym_param) +
        iv_len + UINT32_LEN + src_len + UINT32_LEN + *mac_len;
    IROT_SHM_CREATE(total_len, shm_id);
    IROT_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    //name_len | name | cipher_params | iv_len | iv | src_len | src | mac
    memset(shm_buf, 0, total_len);
    UINT_TO_BIN(name_len, shm_buf); //name_len
    tmp_buf = shm_buf + UINT32_LEN;
    memcpy(tmp_buf, name, name_len); //name
    tmp_buf += name_len;
    memcpy(tmp_buf, mac_params, sizeof(km_sym_param));
    tmp_buf += sizeof(km_sym_param);
    UINT_TO_BIN(iv_len, tmp_buf); //name_len
    tmp_buf = tmp_buf + UINT32_LEN;
    memcpy(tmp_buf, iv, iv_len);
    tmp_buf += iv_len;
    UINT_TO_BIN(src_len, tmp_buf); //name_len
    tmp_buf = tmp_buf + UINT32_LEN;
    memcpy(tmp_buf, src, src_len);
    tmp_buf += src_len;

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_MAC);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, mac_len,
                             DBUS_TYPE_INVALID);

    do {
        dbus_error_init(&error);
        pthread_mutex_lock(&mutex);
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, mac_len, DBUS_TYPE_INVALID);
        dbus_error_parse(error);

        if (result == KM_SUCCESS) {
            memcpy(mac, tmp_buf, *mac_len);
        }

        dbus_message_unref(msgReply);
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_sign(const char *name, const uint32_t name_len, void *sign_params,
             const uint8_t *data, const size_t data_len,
             uint8_t *out, size_t *out_len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t total_len = 0;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint8_t *tmp_buf = NULL;
    uint32_t result;

    if (!out_len || (!out && *out_len)) {
        log_d(TAG, "bad params\n");
        return KM_ERR_BAD_PARAMS;
    }

    //name_len | name | sign_params | data_len | data | out
    total_len = name_len + UINT32_LEN + sizeof(km_sign_param) +
        UINT32_LEN + data_len + *out_len;
    IROT_SHM_CREATE(total_len, shm_id);
    IROT_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    //src_len | src
    memset(shm_buf, 0, total_len);
    UINT_TO_BIN(name_len, shm_buf); //name_len
    tmp_buf = shm_buf + UINT32_LEN;
    memcpy(tmp_buf, name, name_len); //name
    tmp_buf += name_len;
    memcpy(tmp_buf, sign_params, sizeof(km_sign_param));
    tmp_buf += sizeof(km_sign_param);
    UINT_TO_BIN(data_len, tmp_buf);
    tmp_buf += UINT32_LEN;
    memcpy(tmp_buf, data, data_len);
    tmp_buf += data_len;

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_SIGN);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, out_len,
                             DBUS_TYPE_INVALID);

    do {
        dbus_error_init(&error);
        pthread_mutex_lock(&mutex);
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, out_len, DBUS_TYPE_INVALID);
        dbus_error_parse(error);

        if (result == KM_SUCCESS) {
            memcpy(out, tmp_buf, *out_len);
        }

        dbus_message_unref(msgReply);
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_verify(const char *name, const uint32_t name_len, void *sign_params,
               const uint8_t *data, const size_t data_len,
               const uint8_t *signature, const size_t signature_len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t total_len = 0;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint8_t *tmp_buf = NULL;
    uint32_t result;

    //name_len | name | sign_params | data_len | data | signature_len | signature
    total_len = name_len + UINT32_LEN + sizeof(km_sign_param) +
        UINT32_LEN + data_len + UINT32_LEN + signature_len;

    IROT_SHM_CREATE(total_len, shm_id);
    IROT_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    //src_len | src
    memset(shm_buf, 0, total_len);
    UINT_TO_BIN(name_len, shm_buf); //name_len
    tmp_buf = shm_buf + UINT32_LEN;
    memcpy(tmp_buf, name, name_len); //name
    tmp_buf += name_len;
    memcpy(tmp_buf, sign_params, sizeof(km_sign_param));
    tmp_buf += sizeof(km_sign_param);
    UINT_TO_BIN(data_len, tmp_buf);
    tmp_buf += UINT32_LEN;
    memcpy(tmp_buf, data, data_len);
    tmp_buf += data_len;
    UINT_TO_BIN(signature_len, tmp_buf);
    tmp_buf += UINT32_LEN;
    memcpy(tmp_buf, signature, signature_len);
    tmp_buf += data_len;

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_VERIFY);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INVALID);

    do {
        dbus_error_init(&error);
        pthread_mutex_lock(&mutex);
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result, DBUS_TYPE_INVALID);

        dbus_error_parse(error);
        dbus_message_unref(msgReply);
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_asym_encrypt(const char *name, const uint32_t name_len, void *enc_params,
                const uint8_t *src, const size_t src_len,
             uint8_t *dest, size_t *dest_len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t total_len = 0;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint8_t *tmp_buf = NULL;
    uint32_t result;

    if (!dest_len || (!dest && *dest_len)) {
        return KM_ERR_BAD_PARAMS;
    }

    //name_len | name | sign_params | data_len | data | out
    total_len = name_len + UINT32_LEN + sizeof(km_enc_param) +
        UINT32_LEN + src_len + *dest_len;

    IROT_SHM_CREATE(total_len, shm_id);
    IROT_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    //name_len | name | sizeof(km_enc_param) | src_len | src | dest
    memset(shm_buf, 0, total_len);
    UINT_TO_BIN(name_len, shm_buf); //name_len
    tmp_buf = shm_buf + UINT32_LEN;
    memcpy(tmp_buf, name, name_len); //name
    tmp_buf += name_len;
    memcpy(tmp_buf, enc_params, sizeof(km_enc_param));
    tmp_buf += sizeof(km_enc_param);
    UINT_TO_BIN(src_len, tmp_buf);
    tmp_buf += UINT32_LEN;
    memcpy(tmp_buf, src, src_len);
    tmp_buf += src_len;

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_ASYM_ENCRYPT);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, dest_len,
                             DBUS_TYPE_INVALID);
    do {
        dbus_error_init(&error);
        pthread_mutex_lock(&mutex);
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, dest_len, DBUS_TYPE_INVALID);
        dbus_error_parse(error);
        if (result == KM_SUCCESS) {
            memcpy(dest, tmp_buf, *dest_len);
        }

        dbus_message_unref(msgReply);
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_asym_decrypt(const char *name, const uint32_t name_len, void *enc_params,
                const uint8_t *src, const size_t src_len,
               uint8_t *dest, size_t *dest_len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t total_len = 0;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint8_t *tmp_buf = NULL;
    uint32_t result;

    if (!dest_len || (!dest && *dest_len)) {
        return KM_ERR_BAD_PARAMS;
    }

    //name_len | name | enc_params | data_len | data | out
    total_len = name_len + UINT32_LEN + sizeof(km_enc_param) +
        UINT32_LEN + src_len + *dest_len;

    IROT_SHM_CREATE(total_len, shm_id);
    IROT_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    //name_len | name | sizeof(km_enc_param) | src_len | src | dest
    memset(shm_buf, 0, total_len);
    UINT_TO_BIN(name_len, shm_buf); //name_len
    tmp_buf = shm_buf + UINT32_LEN;
    memcpy(tmp_buf, name, name_len); //name
    tmp_buf += name_len;
    memcpy(tmp_buf, enc_params, sizeof(km_enc_param));
    tmp_buf += sizeof(km_enc_param);
    UINT_TO_BIN(src_len, tmp_buf);
    tmp_buf += UINT32_LEN;
    memcpy(tmp_buf, src, src_len);
    tmp_buf += src_len;

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_ASYM_DECRYPT);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, dest_len,
                             DBUS_TYPE_INVALID);
    do {
        dbus_error_init(&error);
        pthread_mutex_lock(&mutex);
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, dest_len, DBUS_TYPE_INVALID);
        dbus_error_parse(error);
        if (result == KM_SUCCESS) {
            memcpy(dest, tmp_buf, *dest_len);
        }

        dbus_message_unref(msgReply);
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_cipher(const char *name, const uint32_t name_len, km_sym_param *cipher_params,
        const uint8_t *iv, const uint32_t iv_len, uint8_t *src, size_t src_len,
        uint8_t *dest, size_t *dest_len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t total_len = 0;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint8_t *tmp_buf = NULL;
    uint32_t result;

    if (!dest_len || (!dest && *dest_len)) {
        return KM_ERR_BAD_PARAMS;
    }

    //name_len | name | cipher_params | iv_len | iv | src_len | src | dest
    total_len = name_len + UINT32_LEN + sizeof(km_sym_param) +
        iv_len + UINT32_LEN + src_len + UINT32_LEN + *dest_len;
    IROT_SHM_CREATE(total_len, shm_id);
    IROT_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    //name_len | name | cipher_params | iv_len | iv | src_len | src | dest
    memset(shm_buf, 0, total_len);
    UINT_TO_BIN(name_len, shm_buf); //name_len
    tmp_buf = shm_buf + UINT32_LEN;
    memcpy(tmp_buf, name, name_len); //name
    tmp_buf += name_len;
    memcpy(tmp_buf, cipher_params, sizeof(km_sym_param));
    tmp_buf += sizeof(km_sym_param);
    UINT_TO_BIN(iv_len, tmp_buf); //iv_len
    tmp_buf = tmp_buf + UINT32_LEN;
    memcpy(tmp_buf, iv, iv_len);
    tmp_buf += iv_len;
    UINT_TO_BIN(src_len, tmp_buf); //src_len
    tmp_buf = tmp_buf + UINT32_LEN;
    memcpy(tmp_buf, src, src_len);
    tmp_buf += src_len;
    memcpy(tmp_buf, dest, *dest_len);

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_CIPHER);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, dest_len,
                             DBUS_TYPE_INVALID);
    do {
        dbus_error_init(&error);
        pthread_mutex_lock(&mutex);
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, dest_len, DBUS_TYPE_INVALID);
        dbus_error_parse(error);

        if (result == KM_SUCCESS) {
            memcpy(dest, tmp_buf, *dest_len);
        }

        dbus_message_unref(msgReply);
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_envelope_begin(void **ctx, const char *name, const uint32_t name_len,
        uint8_t *iv, uint16_t iv_len,
        uint8_t *protected_key, uint32_t *protected_key_len, km_purpose_type is_enc)

{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t total_len = 0;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint8_t *tmp_buf = NULL;
    uint32_t result = 0;
    irot_op_handle_t *op_handle = NULL;

    if (!protected_key_len || (!protected_key && *protected_key_len)) {
        return KM_ERR_BAD_PARAMS;
    }

    total_len = name_len + sizeof(uint32_t) + iv_len + sizeof(uint32_t) + *protected_key_len;
    IROT_SHM_CREATE(total_len, shm_id);
    IROT_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    //name_len | name | begin_len | begin_param | iv_len | iv
    memset(shm_buf, 0, total_len);
    UINT_TO_BIN(name_len, shm_buf);
    tmp_buf = shm_buf + UINT32_LEN;
    memcpy(tmp_buf, name, name_len);
    tmp_buf += name_len;
    UINT_TO_BIN(iv_len, tmp_buf);
    tmp_buf = tmp_buf + UINT32_LEN;
    memcpy(tmp_buf, iv, iv_len);
    tmp_buf += iv_len;
    if (KM_PURPOSE_DECRYPT == is_enc && *protected_key_len) {
        memcpy(tmp_buf, protected_key, *protected_key_len);
    }

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_ENVE_BEGIN);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, protected_key_len,
                             DBUS_TYPE_INT32, &is_enc,
                             DBUS_TYPE_INVALID);

    do {
        dbus_error_init(&error);

        pthread_mutex_lock(&mutex);
        if (!connection) {
            pthread_mutex_unlock(&mutex);
            log_e(TAG, "please first call irot_init\n");
            result = KM_ERR_GENERIC;
            break;
        }
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        if (sizeof(void *) == 8) { //for 64bit
            dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, protected_key_len,
                DBUS_TYPE_INT64, ctx, DBUS_TYPE_INVALID);
        } else if (sizeof(void *) == 4) { //for 32bit
             dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, protected_key_len,
                DBUS_TYPE_INT32, ctx, DBUS_TYPE_INVALID);
        }
        dbus_error_parse(error);
        dbus_message_unref(msgReply);

        if (KM_PURPOSE_ENCRYPT == is_enc && KM_SUCCESS == result && *protected_key_len) {
            memcpy(protected_key, tmp_buf, *protected_key_len);
        }
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_envelope_update(void *ctx, uint8_t *src, uint32_t src_len,
        uint8_t *dest, uint32_t *dest_len)

{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t total_len = 0;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint8_t *tmp_buf = NULL;
    uint32_t result;
    km_key_type key_type;
    uint32_t tmp_dest_len = 0;

    if (!ctx || !dest_len || (!dest && *dest_len)) {
        log_d(TAG, "bad null params\n");
        return KM_ERR_BAD_PARAMS;
    }

    total_len = src_len + UINT32_LEN + *dest_len;
    IROT_SHM_CREATE(total_len, shm_id);
    IROT_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    //src_len | src
    memset(shm_buf, 0, total_len);
    UINT_TO_BIN(src_len, shm_buf);
    tmp_buf = shm_buf + UINT32_LEN;
    memcpy(tmp_buf, src, src_len);

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_ENVE_UPDATE);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    if (sizeof(void *) == 8) {
        dbus_message_append_args(msgQuery,
                DBUS_TYPE_INT64, &ctx,
                DBUS_TYPE_INT32, &shm_id,
                DBUS_TYPE_INT32, dest_len,
                DBUS_TYPE_INVALID);
    } else if (sizeof(void *) == 4) {
        dbus_message_append_args(msgQuery,
                DBUS_TYPE_INT32, &ctx,
                DBUS_TYPE_INT32, &shm_id,
                DBUS_TYPE_INT32, dest_len,
                DBUS_TYPE_INVALID);
    }

    do {
        dbus_error_init(&error);
        pthread_mutex_lock(&mutex);
        if (!connection) {
            pthread_mutex_unlock(&mutex);
            log_e(TAG, "please first call irot_init\n");
            result = KM_ERR_GENERIC;
            break;
        }
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, dest_len, DBUS_TYPE_INVALID);
        dbus_error_parse(error);

        if (result == KM_SUCCESS && *dest_len) {
            memcpy(dest, tmp_buf + src_len, *dest_len);
        }

        dbus_message_unref(msgReply);
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_envelope_finish(void *ctx, uint8_t *src, uint32_t src_len,
        uint8_t *dest, uint32_t *dest_len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t total_len = 0;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    uint8_t *tmp_buf = NULL;
    uint32_t result = 0;

    if (!ctx || !dest_len || (!dest && *dest_len)) {
        return KM_ERR_BAD_PARAMS;
    }

    total_len = src_len + UINT32_LEN + *dest_len;
    IROT_SHM_CREATE(total_len, shm_id);
    IROT_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    //src_len | src
    memset(shm_buf, 0, total_len);
    UINT_TO_BIN(src_len, shm_buf);
    tmp_buf = shm_buf + UINT32_LEN;
    memcpy(tmp_buf, src, src_len);

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_ENVE_FINISH);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    if (sizeof(void *) == 8) { //for 64bit
        dbus_message_append_args(msgQuery,
                DBUS_TYPE_INT64, &ctx,
                DBUS_TYPE_INT32, &shm_id,
                DBUS_TYPE_INT32, dest_len,
                DBUS_TYPE_INVALID);
    } else if (sizeof(void *) == 4) {
         dbus_message_append_args(msgQuery,
                DBUS_TYPE_INT32, &ctx,
                DBUS_TYPE_INT32, &shm_id,
                DBUS_TYPE_INT32, dest_len,
                DBUS_TYPE_INVALID);
    }

    do {
        dbus_error_init(&error);

        pthread_mutex_lock(&mutex);
        if (!connection) {
            pthread_mutex_unlock(&mutex);
            log_e(TAG, "please first call irot_init\n");
            result = KM_ERR_GENERIC;
            break;
        }
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, dest_len, DBUS_TYPE_INVALID);

        dbus_error_parse(error);
        if (result == KM_SUCCESS) {
            memcpy(dest, tmp_buf + src_len, *dest_len);
        }

        dbus_message_unref(msgReply);
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_delete_key(const char *name, const uint32_t name_len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t total_len = 0;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint32_t result = 0;

    total_len = name_len + sizeof(uint32_t);
    IROT_SHM_CREATE(total_len, shm_id);
    IROT_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    //name_len | name
    memset(shm_buf, 0, total_len);
    UINT_TO_BIN(name_len, shm_buf);
    memcpy(shm_buf + UINT32_LEN, name, name_len);

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_DEL_KEY);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INVALID);

    do {
        dbus_error_init(&error);
        pthread_mutex_lock(&mutex);
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error, DBUS_TYPE_INT32, &result, DBUS_TYPE_INVALID);
        dbus_error_parse(error);
        dbus_message_unref(msgReply);
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_delete_all()
{
    log_e(TAG, "not support yet\n");

    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_init()
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    uint32_t result = 0;

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_INIT);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean;
    }

    do {
        dbus_error_init(&error);
        pthread_mutex_lock(&mutex);
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error, DBUS_TYPE_INT32, &result, DBUS_TYPE_INVALID);

        dbus_error_parse(error);
        dbus_message_unref(msgReply);
    } while(0);

clean:
    dbus_message_unref(msgQuery);

    return result;
}

uint32_t km_get_id2(uint8_t *id2, uint32_t *len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint32_t result = 0;
    uint32_t tmp_len = 0;

    if (!len || (!id2 && *len)) {
        return KM_ERR_BAD_PARAMS;
    }

    tmp_len = *len;
    if (tmp_len) {
        IROT_SHM_CREATE(*len, shm_id);
        IROT_SHM_MMAP(shm_id, shm_buf);
        if (shm_buf == NULL) {
            result = KM_ERR_OUT_OF_MEMORY;
            goto clean;
        }
        memset(shm_buf, 0, *len);
    }

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_GET_ID2);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, len,
                             DBUS_TYPE_INVALID);

    do {
        dbus_error_init(&error);

        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error, DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, len, DBUS_TYPE_INVALID);

        dbus_error_parse(error);
        dbus_message_unref(msgReply);
        if (!result) {
            memcpy(id2, shm_buf, *len);
        }
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    if (tmp_len) {
        IROT_SHM_MUNMAP(shm_buf);
    }
clean:
    if (tmp_len) {
        IROT_SHM_DESTROY(shm_id);
    }

    return result;
}

void km_cleanup()
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_INIT);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        goto clean;
    }

    do {
        dbus_error_init(&error);
        pthread_mutex_lock(&mutex);
        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        pthread_mutex_unlock(&mutex);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            break;
        }

        dbus_message_get_args(msgReply, &error, DBUS_TYPE_INVALID);

        dbus_error_parse(error);
        dbus_message_unref(msgReply);
    } while(0);

clean:
    dbus_message_unref(msgQuery);
}

uint32_t km_set_id2(uint8_t *id2, uint32_t len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint32_t result = 0;

    IROT_SHM_CREATE(len, shm_id);
    IROT_SHM_MMAP(shm_id, shm_buf);
    if (shm_buf == NULL) {
        result = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    memcpy(shm_buf, id2, len);

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_SET_ID2);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, &len,
                             DBUS_TYPE_INVALID);

    do {
        dbus_error_init(&error);

        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INVALID);

        dbus_error_parse(error);
        dbus_message_unref(msgReply);
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    IROT_SHM_MUNMAP(shm_buf);
clean:
    IROT_SHM_DESTROY(shm_id);

    return result;
}

uint32_t km_get_attestation(uint8_t *id, uint32_t *id_len)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    int shm_id = 0;
    uint8_t *shm_buf = NULL;
    uint32_t result = 0;
    uint32_t tmp_len = 0;

    if (!id_len || (!id && *id_len)) {
        return KM_ERR_BAD_PARAMS;
    }

    tmp_len = *id_len;
    if (tmp_len) {
        IROT_SHM_CREATE(*id_len, shm_id);
        IROT_SHM_MMAP(shm_id, shm_buf);
        if (shm_buf == NULL) {
            result = KM_ERR_OUT_OF_MEMORY;
            goto clean;
        }
        memset(shm_buf, 0, *id_len);
    }

    msgQuery = dbus_message_new_method_call(
                           SEC_IROT_WELL_KNOWN_NAME,
                           SEC_IROT_OBJECT_PATH,
                           SEC_IROT_INTERFACE_NAME,
                           KM_GET_ATTEST);
    if (msgQuery == NULL) {
        log_e(TAG, "new method call failed\n");
        result = KM_ERR_GENERIC;
        goto clean1;
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_INT32, &shm_id,
                             DBUS_TYPE_INT32, id_len,
                             DBUS_TYPE_INVALID);

    do {
        dbus_error_init(&error);

        msgReply = dbus_connection_send_with_reply_and_block(connection, msgQuery, -1, &error);
        if (dbus_error_is_set(&error)) {
            log_e(TAG, "dbus error (%s)\n", error.message);
            dbus_error_free(&error);
            result = KM_ERR_GENERIC;
            break;
        }

        dbus_message_get_args(msgReply, &error,
                DBUS_TYPE_INT32, &result,
                DBUS_TYPE_INT32, id_len, DBUS_TYPE_INVALID);

        dbus_error_parse(error);
        dbus_message_unref(msgReply);
        if (!result) {
            memcpy(id, shm_buf, *id_len);
        }
    } while(0);

    dbus_message_unref(msgQuery);

clean1:
    if (tmp_len) {
        IROT_SHM_MUNMAP(shm_buf);
    }
clean:
    if (tmp_len) {
        IROT_SHM_DESTROY(shm_id);
    }

    return result;
}
