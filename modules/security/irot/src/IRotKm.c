#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dbus/dbus.h>
#include "tfs_log.h"
#include "IRotKm.h"
#include "irot_private.h"
#include "km.h"

#define SEND_ERR_REPLY(connection, request, str) do { \
    DBusMessage *reply = dbus_message_new_error(request, DBUS_ERROR_FAILED, str); \
    dbus_connection_send(connection, reply, NULL); \
    dbus_message_unref(reply); \
} while(0); \

void irot_generate_key(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    uint8_t *name = NULL;
    uint32_t name_len;
    uint32_t key_type;
    uint8_t *shm_buf = NULL;
    uint32_t arg_len = 0;
    void *arg;
    uint32_t exp_len = 0;
    int shm_id = -1;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &key_type,
                          DBUS_TYPE_INVALID);

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get arg failed");
        return;
    }

    switch(key_type) {
        case KM_AES:
        case KM_HMAC: {
            exp_len = sizeof(km_sym_gen_param);
            break;
        }
        default:
            log_d(TAG, "not support key type %d\n", key_type);
            exp_len = -1;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    name_len = BIN_TO_UINT(shm_buf);
    name = shm_buf + UINT32_LEN;
    arg_len = BIN_TO_UINT(name + name_len);
    arg = name + name_len + UINT32_LEN;

    if (!*name || !name_len || exp_len != arg_len) {
        IROT_SHM_MUNMAP(shm_buf);
        SEND_ERR_REPLY(connection, request, "Illegal argument");
        return;
    }

    ret = km_generate_key(name, name_len, key_type, arg);

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);
}

void irot_import_key(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    uint8_t *name = NULL;
    uint32_t name_len;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    km_key_data_t km_key_data;
    km_format_t format;
    km_key_type key_type;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &format,
                          DBUS_TYPE_INT32, &key_type,
                          DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    name_len = BIN_TO_UINT(shm_buf);
    name = shm_buf + UINT32_LEN;

    if (!*name || !name_len) {
        IROT_SHM_MUNMAP(shm_buf);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    km_key_data.type = key_type;
    switch(key_type) {
        case KM_RSA: {
            km_rsa_key_t *key = &(km_key_data.rsa_key);
            uint8_t *buf = name + name_len;
            //n
            key->n_len = BIN_TO_UINT(buf);
            buf += UINT32_LEN;
            if (key->n_len) {
                key->n = malloc(key->n_len);
                memcpy(key->n, buf, key->n_len);
            }
            buf += key->n_len;
            //e
            key->e_len = BIN_TO_UINT(buf);
            buf += UINT32_LEN;
            if (key->e_len) {
                key->e = malloc(key->e_len);
                memcpy(key->e, buf, key->e_len);
            }
            buf += key->e_len;
            //d
            key->d_len = BIN_TO_UINT(buf);
            buf += UINT32_LEN;
            if (key->d_len) {
                key->d = malloc(key->d_len);
                memcpy(key->d, buf, key->d_len);
            }
            buf += key->d_len;
            //p
            key->p_len = BIN_TO_UINT(buf);
            buf += UINT32_LEN;
            if (key->p_len) {
                key->p = malloc(key->p_len);
                memcpy(key->p, buf, key->p_len);
            }
            buf += key->p_len;
            //q
            key->q_len = BIN_TO_UINT(buf);
            buf += UINT32_LEN;
            if (key->q_len) {
                key->q = malloc(key->q_len);
                memcpy(key->q, buf, key->q_len);
            }
            buf += key->q_len;
            //dp
            key->dp_len = BIN_TO_UINT(buf);
            buf += UINT32_LEN;
            if (key->dp_len) {
                key->dp = malloc(key->dp_len);
                memcpy(key->dp, buf, key->dp_len);
            }
            buf += key->dp_len;
            //dq
            key->dq_len = BIN_TO_UINT(buf);
            buf += UINT32_LEN;
            if (key->dq_len) {
                key->dq = malloc(key->dq_len);
                memcpy(key->dq, buf, key->dq_len);
            }
            buf += key->dq_len;
            //iq
            key->iq_len = BIN_TO_UINT(buf);
            buf += UINT32_LEN;
            if (key->iq_len) {
                key->iq = malloc(key->iq_len);
                memcpy(key->iq, buf, key->iq_len);
            }
            buf += key->iq_len;
            break;
        }
        case KM_AES:
        case KM_HMAC: {
            km_sym_key_t *sym_key = &(km_key_data.sym_key);
            uint32_t key_len = BIN_TO_UINT(name + name_len);

            sym_key->key_bit = key_len << 3;
            sym_key->key = (uint8_t *)malloc(key_len);
            if (!(sym_key->key)) {
                IROT_SHM_MUNMAP(shm_buf);
                SEND_ERR_REPLY(connection, request, "memory out");
                return;
            }
            memcpy(sym_key->key, name + name_len + UINT32_LEN, key_len);
            break;
        }
        default: {
            IROT_SHM_MUNMAP(shm_buf);
            SEND_ERR_REPLY(connection, request, "not support");
            return;
        }
    }

    ret = km_import_key(name, name_len, format,
            &km_key_data, sizeof(km_key_data_t));
    //clean key
    switch(key_type) {
        case KM_RSA: {
            km_rsa_key_t *key = &(km_key_data.rsa_key);
            memset(key->n, 0, key->n_len);
            free(key->n);
            memset(key->e, 0, key->e_len);
            free(key->e);
            memset(key->d, 0, key->d_len);
            free(key->d);
            if (key->p_len && key->p) {
                memset(key->p, 0, key->p_len);
                free(key->p);
            }
            if (key->q_len && key->q) {
                memset(key->q, 0, key->q_len);
                free(key->q);
            }
            if (key->dp_len) {
                memset(key->dp, 0, key->dp_len);
                free(key->dp);
            }
            if (key->dq_len) {
                memset(key->dq, 0, key->dq_len);
                free(key->dq);
            }
            if (key->iq_len) {
                memset(key->iq, 0, key->iq_len);
                free(key->iq);
            }
            break;
        }
        case KM_AES:
        case KM_HMAC: {
            uint8_t *key = km_key_data.sym_key.key;
            if (key) {
                memset(key, 0, km_key_data.sym_key.key_bit >> 3);
                free(key);
            }
            break;
        }
    }

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

    return;
}

#if 0
void irot_export_key(DBusConnection *connection, DBusMessage *request)
{
    return;
}
#endif

void irot_mac(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    uint8_t *name = NULL;
    uint32_t name_len = 0;
    km_sym_param *mac_params;
    uint32_t iv_len = 0;
    uint8_t *iv = NULL;
    size_t src_len = 0;
    uint8_t *src = NULL;
    uint8_t *mac = NULL;
    uint32_t mac_len = 0;
    uint8_t *tmp_buf = NULL;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &mac_len,
                          DBUS_TYPE_INVALID);

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    name_len = BIN_TO_UINT(shm_buf);
    name = shm_buf + UINT32_LEN;
    tmp_buf = name + name_len;
    mac_params = (km_sym_param *)tmp_buf;
    tmp_buf += sizeof(km_sym_param);
    iv_len = BIN_TO_UINT(tmp_buf);
    iv = tmp_buf + UINT32_LEN;
    tmp_buf = iv + iv_len;
    src_len = BIN_TO_UINT(tmp_buf);
    src = tmp_buf + UINT32_LEN;
    mac = src + src_len;

    if (!*name || !name_len || !src_len) {
        IROT_SHM_MUNMAP(shm_buf);
        SEND_ERR_REPLY(connection, request, "get arg failed");
        return;
    }

    ret = km_mac(name, name_len, mac_params, iv, iv_len, src, src_len, mac, &mac_len);

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INT32, &mac_len,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

    return;
}

void irot_sign(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    uint8_t *name = NULL;
    uint32_t name_len = 0;
    km_sign_param *sign_param;
    size_t data_len = 0;
    uint8_t *data = NULL;
    uint8_t *out = NULL;
    size_t out_len = 0;
    uint8_t *tmp_buf = NULL;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &out_len,
                          DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    name_len = BIN_TO_UINT(shm_buf);
    name = shm_buf + UINT32_LEN;
    tmp_buf = name + name_len;
    sign_param = (km_sign_param *)tmp_buf;
    tmp_buf += sizeof(km_sign_param);
    data_len = BIN_TO_UINT(tmp_buf);
    data = tmp_buf + UINT32_LEN;
    out = data + data_len;

    if (!*name || !name_len || !data_len) {
        IROT_SHM_MUNMAP(shm_buf);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    ret = km_sign(name, name_len, sign_param, data, data_len, out, &out_len);

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INT32, &out_len,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

    return;
}
void irot_verify(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    uint8_t *name = NULL;
    uint32_t name_len = 0;
    km_sign_param *sign_param;
    size_t data_len = 0;
    uint8_t *data = NULL;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    uint8_t *tmp_buf = NULL;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INVALID);

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    name_len = BIN_TO_UINT(shm_buf);
    name = shm_buf + UINT32_LEN;
    tmp_buf = name + name_len;
    sign_param = (km_sign_param *)tmp_buf;
    tmp_buf += sizeof(km_sign_param);
    data_len = BIN_TO_UINT(tmp_buf);
    data = tmp_buf + UINT32_LEN;
    tmp_buf = data + data_len;
    signature_len = BIN_TO_UINT(tmp_buf);
    signature = tmp_buf + UINT32_LEN;

    if (!*name || !name_len || !data_len || !signature_len) {
        IROT_SHM_MUNMAP(shm_buf);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    ret = km_verify(name, name_len, sign_param, data, data_len, signature, signature_len);

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

    return;
}
void irot_asym_encrypt(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    uint8_t *name = NULL;
    uint32_t name_len = 0;
    km_enc_param *enc_param;
    size_t src_len = 0;
    uint8_t *src = NULL;
    uint8_t *dest = NULL;
    size_t dest_len = 0;
    uint8_t *tmp_buf = NULL;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &dest_len,
                          DBUS_TYPE_INVALID);

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get arg failed");
        return;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    name_len = BIN_TO_UINT(shm_buf);
    name = shm_buf + UINT32_LEN;
    tmp_buf = name + name_len;
    enc_param = (km_enc_param *)tmp_buf;
    tmp_buf += sizeof(km_enc_param);
    src_len = BIN_TO_UINT(tmp_buf);
    src = tmp_buf + UINT32_LEN;
    dest = src + src_len;

    if (!*name || !name_len || !src_len) {
        IROT_SHM_MUNMAP(shm_buf);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    ret = km_asym_encrypt(name, name_len, enc_param, src, src_len, dest, &dest_len);

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INT32, &dest_len,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

    return;
}

void irot_asym_decrypt(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    uint8_t *name = NULL;
    uint32_t name_len = 0;
    km_enc_param *enc_param;
    size_t src_len = 0;
    uint8_t *src = NULL;
    uint8_t *dest = NULL;
    size_t dest_len = 0;
    uint8_t *tmp_buf = NULL;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &dest_len,
                          DBUS_TYPE_INVALID);

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    name_len = BIN_TO_UINT(shm_buf);
    name = shm_buf + UINT32_LEN;
    tmp_buf = name + name_len;
    enc_param = (km_enc_param *)tmp_buf;
    tmp_buf += sizeof(km_enc_param);
    src_len = BIN_TO_UINT(tmp_buf);
    src = tmp_buf + UINT32_LEN;
    dest = src + src_len;

    if (!*name || !name_len || !src_len) {
        IROT_SHM_MUNMAP(shm_buf);
        SEND_ERR_REPLY(connection, request, "get arg failed");
        return;
    }

    ret = km_asym_decrypt(name, name_len, enc_param, src, src_len, dest, &dest_len);

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INT32, &dest_len,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

    return;
}

void irot_cipher(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    uint8_t *name = NULL;
    uint32_t name_len = 0;
    km_sym_param *cipher_params;
    uint32_t iv_len = 0;
    uint8_t *iv = NULL;
    size_t src_len = 0;
    uint8_t *src = NULL;
    uint8_t *dest = NULL;
    size_t dest_len = 0;
    uint8_t *tmp_buf = NULL;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &dest_len,
                          DBUS_TYPE_INVALID);

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    name_len = BIN_TO_UINT(shm_buf);
    name = shm_buf + UINT32_LEN;
    tmp_buf = name + name_len;
    cipher_params = (km_sym_param *)tmp_buf;
    tmp_buf += sizeof(km_sym_param);
    iv_len = BIN_TO_UINT(tmp_buf);
    iv = tmp_buf + UINT32_LEN;
    tmp_buf = iv + iv_len;
    src_len = BIN_TO_UINT(tmp_buf);
    src = tmp_buf + UINT32_LEN;
    dest = src + src_len;

    if (!*name || !name_len || !src_len) {
        IROT_SHM_MUNMAP(shm_buf);
        SEND_ERR_REPLY(connection, request, "get arg failed");
        return;
    }

    ret = km_cipher(name, name_len, cipher_params, iv, iv_len, src, src_len, dest, &dest_len);

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INT32, &dest_len,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

    return;
}

void irot_envelope_begin(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    uint8_t *name = NULL;
    uint32_t name_len;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    uint8_t *protected_key = NULL;
    uint32_t protected_key_len = 0;
    km_purpose_type is_enc = KM_PURPOSE_ENCRYPT;
    void *ctx = NULL;
    uint32_t begin_len = 0;
    uint32_t iv_len = 0;
    uint8_t *iv = NULL;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &protected_key_len,
                          DBUS_TYPE_INT32, &is_enc,
                          DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) {
        SEND_ERR_REPLY(connection, request, "get arg failed");
        return;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    name_len = BIN_TO_UINT(shm_buf);
    name = shm_buf + UINT32_LEN;
    iv_len = BIN_TO_UINT(name + name_len);
    iv = name + name_len + UINT32_LEN;
    protected_key = iv + iv_len;

    if (!*name) {
        IROT_SHM_MUNMAP(shm_buf);
        SEND_ERR_REPLY(connection, request, "Illegal argument");
        return;
    }

    ret = km_envelope_begin(&ctx, name, name_len, iv, iv_len, protected_key, &protected_key_len, is_enc);

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    if (sizeof(void *) == 8) { //for 64bit
        dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INT32, &protected_key_len,
                             DBUS_TYPE_INT64, &ctx,
                             DBUS_TYPE_INVALID);
    } else if (sizeof(void *) == 4) {
         dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INT32, &protected_key_len,
                             DBUS_TYPE_INT32, &ctx,
                             DBUS_TYPE_INVALID);
    }

    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);
}

void irot_envelope_update(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    void *ctx = NULL;
    uint32_t src_len = 0;
    uint8_t *src = NULL;
    uint8_t *dest = NULL;
    uint32_t dest_len = 0;

    dbus_error_init(&error);

    if (sizeof(void *) == 8) { //for 64bit
        dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT64, &ctx,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &dest_len,
                          DBUS_TYPE_INVALID);
    } else if (sizeof(void *) == 4) {
         dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &ctx,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &dest_len,
                          DBUS_TYPE_INVALID);
    }

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get arg failed");
        return;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    src_len = BIN_TO_UINT(shm_buf);
    src = shm_buf + UINT32_LEN;
    dest = src + src_len;

    ret = km_envelope_update(ctx, src, src_len, dest, &dest_len);

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INT32, &dest_len,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);
}

void irot_envelope_finish(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    void *ctx = NULL;
    uint8_t *src = NULL;
    uint32_t src_len = 0;
    uint8_t *dest = NULL;
    uint32_t dest_len = 0;

    dbus_error_init(&error);

    if (sizeof(void *) == 8) { //for 64bit
        dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT64, &ctx,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &dest_len,
                          DBUS_TYPE_INVALID);
    } else if (sizeof(void *) == 4) {
         dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &ctx,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &dest_len,
                          DBUS_TYPE_INVALID);
    }

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get arg failed");
        return;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    src_len = BIN_TO_UINT(shm_buf);
    src = shm_buf + UINT32_LEN;
    dest = src + src_len;

    ret = km_envelope_finish(ctx, src, src_len, dest, &dest_len);

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INT32, &dest_len,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);
}

//not support in this version
void irot_delete_key(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret = 0;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    uint8_t *name = NULL;
    uint32_t name_len = 0;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INVALID);

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "get arg failed");
        return;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_OUT_OF_MEMORY;
        goto clean;
    }

    name_len = BIN_TO_UINT(shm_buf);
    name = shm_buf + UINT32_LEN;

    ret = km_delete_key(name, name_len);

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

    return;
}

#if 0
void irot_delete_all(DBusConnection *connection, DBusMessage *request)
{
    return;
}
#endif

void irot_init(DBusConnection *connection, DBusMessage *request)
{
    uint32_t result;
    DBusMessage *reply;

    result = km_init();

    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &result,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

    return;
}

void irot_get_id2(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    uint32_t id2_len = 0;
    uint32_t tmp_len = 0;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &id2_len,
                          DBUS_TYPE_INVALID);

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    tmp_len = id2_len;
    if (tmp_len) {
        IROT_SHM_MMAP(shm_id, shm_buf);
        if (!shm_buf) {
            ret = KM_ERR_GENERIC;
            goto clean;
        }
    }

    ret = km_get_id2(shm_buf, &id2_len);

    if (tmp_len) {
        IROT_SHM_MUNMAP(shm_buf);
    }
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INT32, &id2_len,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);
}

void irot_cleanup(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;

    km_cleanup();

    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

    return;
}

void irot_set_id2(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    uint32_t id2_len = 0;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &id2_len,
                          DBUS_TYPE_INVALID);

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    IROT_SHM_MMAP(shm_id, shm_buf);
    if (!shm_buf) {
        ret = KM_ERR_GENERIC;
        goto clean;
    }

    ret = km_set_id2(shm_buf, id2_len);

    IROT_SHM_MUNMAP(shm_buf);
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);

}

void irot_get_attestation(DBusConnection *connection, DBusMessage *request)
{
    DBusMessage *reply;
    DBusError error;
    uint32_t ret;
    int shm_id = -1;
    uint8_t *shm_buf = NULL;
    uint32_t id_len = 0;
    uint32_t tmp_len = 0;

    dbus_error_init(&error);

    dbus_message_get_args(request, &error,
                          DBUS_TYPE_INT32, &shm_id,
                          DBUS_TYPE_INT32, &id_len,
                          DBUS_TYPE_INVALID);

    if (dbus_error_is_set(&error)) {
        dbus_error_free(&error);
        SEND_ERR_REPLY(connection, request, "Illegal arguments");
        return;
    }

    tmp_len = id_len;
    if (tmp_len) {
        IROT_SHM_MMAP(shm_id, shm_buf);
        if (!shm_buf) {
            ret = KM_ERR_GENERIC;
            goto clean;
        }
    }

    ret = km_get_attestation(shm_buf, &id_len);

    if (tmp_len) {
        IROT_SHM_MUNMAP(shm_buf);
    }
clean:
    reply = dbus_message_new_method_return(request);
    dbus_message_append_args(reply,
                             DBUS_TYPE_INT32, &ret,
                             DBUS_TYPE_INT32, &id_len,
                             DBUS_TYPE_INVALID);
    dbus_connection_send(connection, reply, NULL);
    dbus_message_unref(reply);
}

