/*
 * Copyright (c) 2014-2016 Alibaba Group. All rights reserved.
 * License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "sysconfig.h"
#include "hiredis/hiredis.h"
#include "parson.h"
#include "abp_nodes.h"
#include "digest/utils_md5.h"
#include "aes.h"
#include "gwiotapi.h"

#if defined(ENABLE_ADVANCED_SECURITY)
#include "keychain.h"
#endif

#define ENABLE_NODES_DECRYPT

#define ABP_NODES_FILE_NAME    "abp_nodes.json"

#define PROTOCOL_VERSION    2

static const char deveui_key[]   = {"lora:ns:device:%llx"};
static const char devaddr_key[]  = {"lora:ns:devaddr:%llx"};
static const char md5sum_key[]  = {"lora:nodesfile:md5sum"};
static const char deveui_value[] = {
"{\"MACVersion\":\"%s\",\
\"DevAddr\":\"%llx\",\
\"DevEUI\":\"%llx\",\
\"FNwkSIntKey\":\"%s\",\
\"SNwkSIntKey\":\"%s\",\
\"NwkSEncKey\":\"%s\",\
\"AppSKey\":\"%s\",\
\"Mode\":\"%s\",\
\"FCntUp\":%u,\
\"NFCntDown\":%u,\
\"AFCntDown\":%u,\
\"ConfFCnt\":%u,\
\"SkipFCntValidation\":true,\
\"EnabledUplinkChannels\":[0,1,2,3,4,5,6,7]\
}"
};

static const char *ssl_ca_crt = \
{
    \
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG\r\n" \
    "A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\r\n" \
    "b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw\r\n" \
    "MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\r\n" \
    "YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT\r\n" \
    "aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ\r\n" \
    "jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp\r\n" \
    "xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp\r\n" \
    "1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG\r\n" \
    "snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ\r\n" \
    "U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8\r\n" \
    "9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\r\n" \
    "BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B\r\n" \
    "AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz\r\n" \
    "yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE\r\n" \
    "38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP\r\n" \
    "AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad\r\n" \
    "DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME\r\n" \
    "HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==\r\n" \
    "-----END CERTIFICATE-----"
};

redisContext *redis_ctx = NULL;
abp_list_t  abp_list;

uint32_t abp_file_size = 0;
char abp_file_url[1024];
char abp_file_md5[33];
uint8_t dev_key[17];
uint8_t ack_token_h = 0;
uint8_t ack_token_l = 0;
uint32_t gw_eui_h = 0;
uint32_t gw_eui_l = 0;
uint8_t abp_out_enable = 1;

static void *md5_init(void)
{
    iot_md5_context *ctx = HAL_Malloc(sizeof(iot_md5_context));
    if (NULL == ctx) {
        return NULL;
    }

    utils_md5_init(ctx);
    utils_md5_starts(ctx);

    return ctx;
}

static void md5_update(void *md5, const char *buf, size_t buf_len)
{
    utils_md5_update(md5, (unsigned char *)buf, buf_len);
}

static void md5_finalize(void *md5, char *output_str)
{
    int i;
    unsigned char buf_out[16];
    utils_md5_finish(md5, buf_out);

    for (i = 0; i < 16; ++i) {
        output_str[i * 2] = utils_hb2hex(buf_out[i] >> 4);
        output_str[i * 2 + 1] = utils_hb2hex(buf_out[i]);
    }
    output_str[32] = '\0';
}

static void md5_deinit(void *md5)
{
    if (NULL != md5) {
        HAL_Free(md5);
    }
}

static int redis_connect(void)
{
    redisReply *reply = NULL;
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds

    redis_ctx = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
    if ((NULL == redis_ctx) || redis_ctx->err) {
        if (redis_ctx) {
            log_err("Connection error: %s", redis_ctx->errstr);
            redisFree(redis_ctx);
            redis_ctx = NULL;
        } else {
            log_err("Connection error: can't allocate redis context");
        }
        return -1;
    }

    /* PING server */
    reply = redisCommand(redis_ctx, "PING");
    if (reply != NULL) {
        log_info("PING: %s", reply->str);
        freeReplyObject(reply);
    }

    return 0;
}

static int redis_disconnect(void)
{
    if (redis_ctx) {
        redisFree(redis_ctx);
        redis_ctx = NULL;
    }

    return 0;
}

static int redis_set(const char *key, const char *value)
{
    redisReply *reply = NULL;

    if (NULL == redis_ctx) {
        log_err("redis context is NULL");
        return -1;
    }

    if ((NULL == key) || (NULL == value)) {
        log_err("key or value is NULL");
        return -1;
    }

    log_info("redis_set key:%s", key);

    reply = redisCommand(redis_ctx, "SET %s %s", key, value);
    if (reply != NULL) {
        log_info("reply: %s", reply->str);
        freeReplyObject(reply);
    }

    return 0;
}

static int redis_get(const char *key, char *value, uint32_t size)
{
    redisReply *reply = NULL;

    if (NULL == redis_ctx) {
        log_err("redis context is NULL");
        return -1;
    }

    if ((NULL == key) || (NULL == value)) {
        log_err("key or value is NULL");
        return -1;
    }

    log_info("redis_get key:%s", key);

    reply = redisCommand(redis_ctx, "GET %s", key);
    if (reply != NULL) {
        // log_info("reply: %s", reply->str);
        if (reply->str != NULL) {
            strncpy(value, reply->str, size);
            value[size] = 0;
        }
        freeReplyObject(reply);
    }

    return 0;
}

static int redis_sadd(const char *key, const char *value)
{
    redisReply *reply = NULL;
    int is_exist = 0;

    if (NULL == redis_ctx) {
        log_err("redis context is NULL");
        return -1;
    }

    if ((NULL == key) || (NULL == value)) {
        log_err("key or value is NULL");
        return -1;
    }

    log_info("redis_sadd key:%s, value:%s", key, value);

    reply = redisCommand(redis_ctx, "SISMEMBER %s %s", key, value);
    if (reply != NULL) {
        if ((reply->type == REDIS_REPLY_INTEGER) && (reply->integer == 1)) {
            is_exist = 1;
        }
        freeReplyObject(reply);
    }

    if (is_exist == 1) {
        log_info("SREM key:%s, value:%s", key, value);
        reply = redisCommand(redis_ctx, "SREM %s %s", key, value);
        if (reply != NULL) {
            //log_info("reply: %s", reply->str);
            freeReplyObject(reply);
        }
    }

    reply = redisCommand(redis_ctx, "SADD %s %s", key, value);
    if (reply != NULL) {
        //log_info("reply: %s", reply->str);
        freeReplyObject(reply);
    }

    return 0;
}

static int redis_srem(const char *key, const char *value)
{
    redisReply *reply = NULL;

    if (NULL == redis_ctx) {
        log_err("redis context is NULL");
        return -1;
    }

    if ((NULL == key) || (NULL == value)) {
        log_err("key or value is NULL");
        return -1;
    }

    log_info("redis_srem key:%s, value:%s", key, value);

    reply = redisCommand(redis_ctx, "SREM %s %s", key, value);
    if (reply != NULL) {
        //log_info("reply: %s", reply->str);
        freeReplyObject(reply);
    }

    return 0;
}

static int redis_node_update(abp_node_pt pnode)
{
    JSON_Value *root_val = NULL;
    JSON_Value *val = NULL;
    char key[256];
    char value[4096];
    char old_value[4096];
    int ret = 0;
    abp_node_t old_node;
    const char *str;

    memset(key, 0, sizeof(key));
    sprintf(key, deveui_key, pnode->deveui);

    memset(old_value, 0, sizeof(old_value));
    redis_get(key, old_value, 4096);
    if (strlen(old_value) > 0) {
        root_val = json_parse_string_with_comments(old_value);
        if (root_val != NULL) {
            memset(&old_node, 0, sizeof(abp_node_t));

            str = json_object_get_string(json_value_get_object(root_val), "Mode");
            if (str != NULL) {
                strncpy(old_node.mode, str, 8);
                if (strlen(pnode->mode) == 0) {
                    strncpy(pnode->mode, old_node.mode, 8);
                    log_info("use old mode: %s", old_node.mode);
                }
            }

            str = json_object_get_string(json_value_get_object(root_val), "MACVersion");
            if (str != NULL) {
                strncpy(old_node.version, str, 8);
                if (strlen(pnode->version) == 0) {
                    strncpy(pnode->version, old_node.version, 8);
                    log_info("use old version: %s", old_node.version);
                }
            }

            str = json_object_get_string(json_value_get_object(root_val), "AppSKey");
            if (str != NULL) {
                strncpy(old_node.appskey, str, 128);
                if (strlen(pnode->appskey) == 0) {
                    strncpy(pnode->appskey, old_node.appskey, 128);
                    log_info("use old appskey: %s", old_node.appskey);
                }
            }

            str = json_object_get_string(json_value_get_object(root_val), "NwkSEncKey");
            if (str != NULL) {
                strncpy(old_node.nwkskey, str, 128);
                if (strlen(pnode->nwkskey) == 0) {
                    strncpy(pnode->nwkskey, old_node.nwkskey, 128);
                    log_info("use old nwkskey: %s", old_node.nwkskey);
                }
            }

            val = json_object_get_value(json_value_get_object(root_val), "FCntUp");
            if (NULL != val) {
                old_node.fcntup = (uint32_t)json_value_get_number(val);
                log_info("old fcntup: %d", old_node.fcntup);
            }

            val = json_object_get_value(json_value_get_object(root_val), "NFCntDown");
            if (NULL != val) {
                old_node.nfcntdown = (uint32_t)json_value_get_number(val);
                log_info("old nfcntdown: %d", old_node.nfcntdown);
            }

            val = json_object_get_value(json_value_get_object(root_val), "AFCntDown");
            if (NULL != val) {
                old_node.afcntdown = (uint32_t)json_value_get_number(val);
                log_info("old afcntdown: %d", old_node.afcntdown);
            }

            val = json_object_get_value(json_value_get_object(root_val), "ConfFCnt");
            if (NULL != val) {
                old_node.conffcnt = (uint32_t)json_value_get_number(val);
                log_info("old conffcnt: %d", old_node.conffcnt);
            }

            if ((strcmp(pnode->nwkskey, old_node.nwkskey) != 0)
                || (strcmp(pnode->appskey, old_node.appskey) != 0)) {
                pnode->fcntup = 0;
                pnode->nfcntdown = 0;
                pnode->afcntdown = 0;
                pnode->conffcnt = 0;
            } else {
                pnode->fcntup = old_node.fcntup;
                pnode->nfcntdown = old_node.nfcntdown;
                pnode->afcntdown = old_node.afcntdown;
                pnode->conffcnt = old_node.conffcnt;
            }
        }
    }

    if ((strlen(pnode->version) == 0) || (strlen(pnode->mode) == 0)
        || (strlen(pnode->appskey) == 0) || (strlen(pnode->appskey) == 0)) {
        log_err("the node data invalid");
        return -1;
    }

    memset(value, 0, sizeof(value));
    sprintf(value, deveui_value, pnode->version, pnode->devaddr,
        pnode->deveui, pnode->nwkskey, pnode->nwkskey, pnode->nwkskey,
        pnode->appskey, pnode->mode, pnode->fcntup, pnode->nfcntdown, pnode->afcntdown, pnode->conffcnt);

    ret = redis_set(key, value);
    if (ret != 0) {
        log_err("redis_set error, key:%s", key);
    }
    
    memset(key, 0, sizeof(key));
    sprintf(key, devaddr_key, pnode->devaddr);
    sprintf(value, "%llx", pnode->deveui);
    ret = redis_sadd(key, value);
    if (ret != 0) {
        log_err("redis_sadd error, key:%s, value:%s", key, value);
    }

    return 0;
}

static int redis_node_delete(abp_node_pt pnode)
{
    char key[256];
    char value[256];
    int ret = 0;

    memset(key, 0, sizeof(key));
    sprintf(key, devaddr_key, pnode->devaddr);
    sprintf(value, "%llx", pnode->deveui);
    ret = redis_srem(key, value);
    if (ret != 0) {
        log_err("redis_srem error, key:%s, value:%s", key, value);
    }

    return 0;
}

static int nodes_decrypt_data(const char* in, char* out, int out_len)
{
    uint8_t input[512] = {0};
    struct AES_ctx ctx;
    int i = 0;
    int size = 0;

    if ((in == NULL) || (out == NULL) || (strlen(in) <= 0)) {
        log_err("param is invalid");
        return -1;
    }

    if (strlen((char *)dev_key) <= 0) {
        log_err("param is invalid");
        return -1;
    }

    if ((strlen(in) % 16) != 0) {
        log_err("input data is invalid");
        return -1;
    }

    size = strlen(in) / 2;
    //log_info("in size: %d", size);
    //log_info("in: %s", in);
    memset(input, 0, sizeof(input));
    for (i = 0; i < strlen(in); i = i + 2) {
        sscanf(in + i, "%02hhx", &input[i/2]);
    }

    AES_init_ctx(&ctx, dev_key);

    for(i = 0; i < size / 16; i++) {
        AES_ECB_decrypt(&ctx, input + 16 * i);
    }

    if (out_len <= 0) {
        out_len = size;
    }
    for(i = 0; i < out_len; i++) {
        sprintf((char *)(out + 2 * i), "%02x", input[i]);
    }
    //log_info("decrypt, size: %d, out_len: %d", size, out_len);
    //log_info("out: %s", out);

    return 0;
}

static int nodes_item_parse(const JSON_Object *object, abp_node_pt pnode) 
{
    const char *str;
    uint64_t value = 0;
    char out[512] = {0};

    str = json_object_get_string(object, "DevEUI");
    if (str != NULL) {
        #if defined(ENABLE_NODES_DECRYPT)
        memset(out, 0x0, sizeof(out));
        if (nodes_decrypt_data(str, out, 8) == 0) {
            sscanf(out, "%llx", &value);
        }
        #else
        sscanf(str, "%llx", &value);
        #endif 
        log_info("deveui: %llx", value);
        pnode->deveui = value;
    }

    str = json_object_get_string(object, "DevAddr");
    if (str != NULL) {
        #if defined(ENABLE_NODES_DECRYPT)
        memset(out, 0x0, sizeof(out));
        if (nodes_decrypt_data(str, out, 4) == 0) {
            sscanf(out, "%llx", &value);
        }
        #else
        sscanf(str, "%llx", &value);
        #endif
        log_info("devaddr: %llx", value);
        pnode->devaddr = value;
    }

    str = json_object_get_string(object, "AppSKey");
    if (str != NULL) {
        #if defined(ENABLE_ADVANCED_SECURITY)
        /* no decrypt, use keychain stored for decrypt in native NS */
        strncpy(pnode->appskey, str, 128);
        #else
            #if defined(ENABLE_NODES_DECRYPT)
            memset(out, 0x0, sizeof(out));
            if (nodes_decrypt_data(str, out, 16) == 0) {
                strncpy(pnode->appskey, out, 32);
            }
            #else
            strncpy(pnode->appskey, str, 128);
            #endif
        #endif
        //log_info("appskey: %s", list->nodes[i].appskey);
    }

    str = json_object_get_string(object, "NwkSKey");
    if (str != NULL) {
        #if defined(ENABLE_ADVANCED_SECURITY)
        /* no decrypt, use keychain stored for decrypt in native NS */
        strncpy(pnode->nwkskey, str, 128);
        #else
            #if defined(ENABLE_NODES_DECRYPT)
            memset(out, 0x0, sizeof(out));
            if (nodes_decrypt_data(str, out, 16) == 0) {
                strncpy(pnode->nwkskey, out, 32);
            }
            #else
            strncpy(pnode->nwkskey, str, 128);
            #endif
        #endif
        //log_info("nwkskey: %s", list->nodes[i].nwkskey);
    }

    str = json_object_get_string(object, "Mode");
    if (str != NULL) {
        log_info("mode: %s", str);
        strncpy(pnode->mode, str, 8);
    }

    str = json_object_get_string(object, "MACVersion");
    if (str != NULL) {
        log_info("macversion: %s", str);
        strncpy(pnode->version, str, 8);
    }

    return 0;
}

static int nodes_update_msg_proc(const JSON_Object *object, const char *name) 
{
    JSON_Array *node_array = NULL;
    JSON_Object *node_obj = NULL;
    int i = 0;
    int ret = 0;
    int node_cnt = 0;
    abp_node_t update_node;

    node_array = json_object_get_array(object, name);
    if (node_array != NULL) {
        node_cnt = (int)json_array_get_count(node_array);
        
        if (node_cnt <= 0) {
            log_err("no nodes contains");
            return -1;
        }
        log_info("contains nodes count: %u", node_cnt);

        ret = redis_connect();
        if (ret != 0) {
            log_err("redis_connect error");
            return -1;
        }

        for (i = 0; i < node_cnt; i++) {
            node_obj = json_array_get_object(node_array, i);
            if (node_obj != NULL) {
                memset(&update_node, 0, sizeof(abp_node_t));
                nodes_item_parse(node_obj, &update_node);

                if ((update_node.deveui != 0) && (update_node.devaddr != 0)) {
                    redis_node_update(&update_node);
                }
            }
        }

        redis_disconnect();
        return 1;
    }

    return 0;
}

static int nodes_delete_msg_proc(const JSON_Object *object, const char *name) 
{
    JSON_Array *node_array = NULL;
    JSON_Object *node_obj = NULL;
    int i = 0;
    int ret = 0;
    int node_cnt = 0;
    abp_node_t delete_node;

    node_array = json_object_get_array(object, name);
    if (node_array != NULL) {
        node_cnt = (int)json_array_get_count(node_array);
        if (node_cnt <= 0) {
            log_err("no nodes contains");
            return -1;
        }
        log_info("contains nodes count: %u", node_cnt);

        ret = redis_connect();
        if (ret != 0) {
            log_err("redis_connect error");
            return -1;
        }

        for (i = 0; i < node_cnt; i++) {
            node_obj = json_array_get_object(node_array, i);
            if (node_obj != NULL) {
                memset(&delete_node, 0, sizeof(abp_node_t));
                nodes_item_parse(node_obj, &delete_node);

                if ((delete_node.deveui != 0) && (delete_node.devaddr != 0)) {
                    redis_node_delete(&delete_node);
                }
            }
        }

        redis_disconnect();
    }

    return 0;
}

static int nodes_out_msg_proc(const JSON_Object *object, const char *name) 
{
    JSON_Object *node_obj = NULL;
    JSON_Value *val = NULL;
    uint8_t enable = 1;

    node_obj = json_object_get_object(object, name);
    if (NULL != node_obj) {
        val = json_object_get_value(node_obj, "enable");
        if (val != NULL) {
            enable = (uint8_t)json_value_get_number(val);
            if (enable == 0) {
                abp_out_enable = 0;
            } else {
                abp_out_enable = 1;
            }
            log_info("abp_out_enable: %d", abp_out_enable);
        }

        return 1;
    }

    return 0;
}

static int util_strtol(char *str, uint32_t *in_val)
{
    int val;

    errno = 0;
    val = strtoll(str, NULL, 16);

    if ((errno == ERANGE && (val == LLONG_MAX || val == LLONG_MIN))
        || (errno != 0 && val == 0)) {
        perror("strtoll");
        return -1;
    }

    *in_val = val;
    return 0;
}

static char g_abp_msg_ack[256];
extern int publish_gwmp_msg_uplink(char *msg_buf, int msg_len);
int abp_send_msg_ack(char *error_str) {
    char buff_ack[256];
    int buff_index;
    int j = 0;

    memset(buff_ack, 0, sizeof(buff_ack));

    buff_ack[0] = PROTOCOL_VERSION;
    buff_ack[1] = ack_token_h;
    buff_ack[2] = ack_token_l;
    buff_ack[3] = ABP_MSGID_UP;
    *(uint32_t *)(buff_ack + 4) = gw_eui_h;
    *(uint32_t *)(buff_ack + 8) = gw_eui_l;
    buff_index = 12;

    if (error_str != NULL) {
        memcpy((void *)(buff_ack + buff_index), (void *)"{\"set_ack\":{", 12);
        buff_index += 12;
        j = snprintf((char *)(buff_ack + buff_index), sizeof(buff_ack) - buff_index, "\"error\":%s", error_str);
        if (j > 0) {
            buff_index += j;
        }
        memcpy((void *)(buff_ack + buff_index), (void *)"}}", 2);
        buff_index += 2;
    }

    buff_ack[buff_index] = 0;
    memcpy(g_abp_msg_ack, buff_ack, sizeof(buff_ack));
    publish_gwmp_msg_uplink(g_abp_msg_ack, buff_index);

    return 0;
}

static char mqtt_ca_crt[2048];
static const char *ssl_ca_get(void)
{
    /* Begin add for Edge CN */
    FILE *fp = NULL;
    uint32_t file_len = 0;

    memset(mqtt_ca_crt, 0x0, sizeof(mqtt_ca_crt));

    fp = fopen("mqtt-ca.crt", "rb");
    if (NULL != fp) {
        file_len = fread(mqtt_ca_crt, 1, sizeof(mqtt_ca_crt) - 1, fp); 
        if (file_len > 0) {
            printf("use mqtt-ca.crt file\n");
            fclose(fp);
            fp = NULL;
            return mqtt_ca_crt;
        }
        fclose(fp);
        fp = NULL;
    }
    /* End */

    return ssl_ca_crt;
}

static void *file_dl_init(const char *url)
{
    file_http_pt h_fdc = NULL;

    h_fdc = HAL_Malloc(sizeof(file_http_t));
    if (NULL == h_fdc) {
        log_err("allocate for h_fdc failed");
        return NULL;
    }

    memset(h_fdc, 0, sizeof(file_http_t));
    h_fdc->http.header = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" \
                         "Accept-Encoding: gzip, deflate\r\n";

    h_fdc->url = url;

    return h_fdc;
}

static int32_t file_dl_fetch(void *handle, char *buf, uint32_t buf_len, uint32_t timeout_s)
{
    int diff = 0;
    file_http_pt h_fdc = (file_http_pt)handle;

    h_fdc->http_data.response_buf = buf;
    h_fdc->http_data.response_buf_len = buf_len;
    diff = h_fdc->http_data.response_content_len - h_fdc->http_data.retrieve_len;;

    if (0 != httpclient_common(&h_fdc->http, h_fdc->url, 443, ssl_ca_get(), HTTPCLIENT_GET, timeout_s * 1000,
                               &h_fdc->http_data)) {
        log_err("fetch file failed");
        return -1;
    }

    return h_fdc->http_data.response_content_len - h_fdc->http_data.retrieve_len - diff;
}

static int file_dl_deinit(void *handle)
{
    if (NULL != handle) {
        HAL_Free(handle);
    }

    return 0;
}

static int nodes_file_parse(const char *nodes_file) 
{
    const char nodes_obj_name[] = "nodeInfo";
    JSON_Value *root_val = NULL;
    JSON_Array *node_array = NULL;
    JSON_Object *node_obj = NULL;
    int i = 0;
    int node_cnt = 0;
    abp_list_pt list = &abp_list;

    root_val = json_parse_file_with_comments(nodes_file);
    if (root_val == NULL) {
        log_err("%s is not a valid JSON file", nodes_file);
        return -1;
    }

    node_array = json_object_get_array(json_value_get_object(root_val), nodes_obj_name);
    if (node_array != NULL) {
        node_cnt = (int)json_array_get_count(node_array);
        if (node_cnt <= 0) {
            log_err("no nodes contains");
            json_value_free(root_val);
            return -1;
        }

        log_info("contains nodes info count: %u", node_cnt);
        memset(list, 0, sizeof(abp_list_t));
        list->num = node_cnt;

        for (i = 0; i < node_cnt; i++) {
            node_obj = json_array_get_object(node_array, i);

            nodes_item_parse(node_obj, &list->nodes[i]);
        }
    }

    json_value_free(root_val);
    return 0;
}

int nodes_file_md5sum(char* md5sum)
{
    void *ch_md5 = NULL;
    char md5_str[33] = {0};
    char buf[4096] = {0};
    uint32_t readed = 0;
    uint32_t len = 0;
    FILE *fp = NULL;
    
    fp = fopen(ABP_NODES_FILE_NAME, "rb");
    if (NULL == fp) {
        log_err("fopen file failed");
        return -1;
    }    

    ch_md5 = md5_init();
    if (NULL == ch_md5) {
        log_err("md5_init failed");
        fclose(fp);
        fp = NULL;
        return -1;
    }

    while (1) {
        memset(buf, 0, sizeof(buf));	
        len = fread(buf, 1, sizeof(buf), fp);
        if (len <= 0) {
            break;
        }
        log_info("fread len:%d", len);
        readed += len;
        md5_update(ch_md5, buf, len);
    }

    if (readed > 0) {
        md5_finalize(ch_md5, md5_str);
        strncpy(md5sum, md5_str, 32);
        md5sum[32] = 0;
    }

    md5_deinit(ch_md5);
    ch_md5 = NULL;
    fclose(fp);
    fp = NULL;

    return 0;
}

static int nodes_write_redis(void)
{
    char md5str[33];
    char md5sum[33];
    int update = 1;
    int i = 0;
    int ret = 0;
    abp_list_pt list = &abp_list;

    memset(md5sum, 0, sizeof(md5sum));
    nodes_file_md5sum(md5sum);
    log_info("file md5sum: %s", md5sum);

    ret = redis_connect();
    if (ret != 0) {
        log_err("redis_connect error");
        return -1;
    }

    memset(md5str, 0, sizeof(md5str));
    redis_get(md5sum_key, md5str, 32);
    log_info("redis md5sum:%s", md5str);
    if ((strlen(md5str) > 0) && (strlen(md5sum) > 0)) {
        if (0 == strcmp(md5sum, md5str)) {
            log_info("md5sum no change, no need write redis");
            update = 0; 
        } else {
            log_info("md5sum changed");
            update = 1;
        }
    }

    if (update == 1) {
        for (i = 0; i < (int)list->num; i++) {
            redis_node_update(&list->nodes[i]);
        }

        if (strlen(md5sum) > 0) {
            ret = redis_set(md5sum_key, md5sum);
            if (ret != 0) {
                log_err("redis_set error, key:%s", md5sum_key);
            }
        }
    }

    redis_disconnect();

    return 0;
}

int abp_file_download(void)
{
    char *url = abp_file_url;
    char *md5sum = abp_file_md5;
    uint32_t size = abp_file_size;
    void *ch_fetch = NULL;
    void *ch_md5 = NULL;
    char md5_str[33] = {0};
    char buf[4096] = {0};
    uint32_t fetched = 0;
    uint32_t len = 0;
    int ret = 0;
    FILE *fp = NULL;

    if ((0 == strlen(url)) || (0 == size)) {
        log_err("invalid param");
        return -1;
    }
    
    fp = fopen(ABP_NODES_FILE_NAME, "w");
    if (NULL == fp) {
        log_err("fopen file failed");
        return -1;
    }    

    ch_md5 = md5_init();
    if (NULL == ch_md5) {
        log_err("md5_init failed");
        fclose(fp);
        fp = NULL;
        return -1;
    }

    ch_fetch = file_dl_init(url);
    if (NULL == ch_fetch) {
        log_err("file_dl_init failed");
        md5_deinit(ch_md5);
        ch_md5 = NULL;
        fclose(fp);
        fp = NULL;
        return -1;
    }

    do {
        len = file_dl_fetch(ch_fetch, buf, 4096, 1);
        if (len > 0) {
            fetched += len;

            ret = fwrite(buf, 1, len, fp);
            if (ret != len) {
                log_err("fwrite failed, %d != %d", ret, len);
                break;
            }
            md5_update(ch_md5, buf, len);
            log_info("fetched size:%d", fetched);
        } else if (ret < 0) {
            log_err("file_dl_fetch failed");
            break;
        }

        HAL_SleepMs(100);
    } while (fetched < size);

    if ((fetched > 0) && (fetched >= size)) {
        md5_finalize(ch_md5, md5_str);
        log_info("origin=%s, now=%s", md5sum, md5_str);
        if (0 == strcmp(md5sum, md5_str)) {
            log_info("abp file md5 check ok");
            ret = 0;
        } else {
            log_err("abp file md5 check failed");
            ret = -1;
        }
    } else {
        log_err("abp file fetch failed");
        ret = -1;
    }

    md5_deinit(ch_md5);
    ch_md5 = NULL;
    fclose(fp);
    fp = NULL;
    file_dl_deinit(ch_fetch);
    ch_fetch = NULL;

    return ret;
}

int abp_file_conf(const char *msg_buf, uint16_t msg_len)
{
    JSON_Value *root_val = NULL;
    JSON_Object *set_obj = NULL;
    JSON_Object *conf_obj = NULL;
    JSON_Value *val = NULL;
    uint8_t msg_id = 0;
    const char *str;
    int ret = 0;

    if (msg_len < 4) {
        log_err("ignoring invalid packet, len: %d", msg_len);
        return -1;
    }

    msg_id = msg_buf[3];
    ack_token_h = msg_buf[1];
    ack_token_l = msg_buf[2];

    log_info("abp_file_conf msg_id: %d", msg_id);
    if (msg_id == ABP_MSGID_DOWN) {
        log_info("abp file conf msg: %s", (msg_buf + 4));
        root_val = json_parse_string_with_comments((const char *)(msg_buf + 4));
        if (root_val == NULL) {
            log_err("invalid JSON");
            return -1;
        }

        set_obj = json_object_get_object(json_value_get_object(root_val), "set");
        if (NULL != set_obj) {
            /* abpf msg proc */
            conf_obj = json_object_get_object(set_obj, "abpf");
            if (NULL != conf_obj) {
                str = json_object_get_string(conf_obj, "url");
                if (str != NULL) {
                    memset(abp_file_url, 0, sizeof(abp_file_url));
                    strncpy(abp_file_url, str, sizeof(abp_file_url) - 1);
                    log_info("abp_file_url: %s", abp_file_url);
                }

                val = json_object_get_value(conf_obj, "size");
                if (val != NULL) {
                    abp_file_size = (uint32_t)json_value_get_number(val);
                    log_info("abp_file_size: %d", abp_file_size);
                }

                str = json_object_get_string(conf_obj, "md5");
                if (str != NULL) {
                    memset(abp_file_md5, 0, sizeof(abp_file_md5));
                    strncpy(abp_file_md5, str, sizeof(abp_file_md5) - 1);
                    log_info("abp_file_md5: %s", abp_file_md5);
                }

                json_value_free(root_val);
                return 1;
            }

            /* abpadd msg proc */
            ret = nodes_update_msg_proc(set_obj, "abpadd");
            if (ret == 1) {
                abp_send_msg_ack(NULL);
            } else if (ret == -1) {
                abp_send_msg_ack("abpadd:error");
            }

            /* abpupd msg proc */
            ret = nodes_update_msg_proc(set_obj, "abpupd");
            if (ret == 1) {
                abp_send_msg_ack(NULL);
            } else if (ret == -1) {
                abp_send_msg_ack("abpupd:error");
            }

            /* abpdel msg proc */
            nodes_delete_msg_proc(set_obj, "abpdel");
            if (ret == 1) {
                abp_send_msg_ack(NULL);
            } else if (ret == -1) {
                abp_send_msg_ack("abpdel:error");
            }

            /* abpout msg proc */
            nodes_out_msg_proc(set_obj, "abpout");
            if (ret == 1) {
                abp_send_msg_ack(NULL);
            } else if (ret == -1) {
                abp_send_msg_ack("abpout:error");
            }
        }

        json_value_free(root_val);
    }

    return 0;
}

int abp_redis_init(void) 
{
    int ret = 0;

    ret = nodes_file_parse(ABP_NODES_FILE_NAME);
    if (ret != 0) {
        log_err("parse abp nodes file failed");
        return -1;
    }

    ret = nodes_write_redis();
    if (ret != 0) {
        log_err("write abp nodes failed");
        return -1;
    }

    return 0;
}

int abp_key_init(void)
{
    char eui_h_str[9] = {'\0'};
    char eui_l_str[9] = {'\0'};
    aliot_gw_device_info_t dev_info;
    aliot_gw_auth_info_t auth_info;
    uint32_t ret = 0;
    #if defined(ENABLE_ADVANCED_SECURITY)
    char *key_name = "device_secret";
    kc_key_type_t key_type = KEY_CHAIN_USERDATA;
    uint8_t out_buf[17] = {0};
    uint32_t out_buf_len = 0;
    #endif

    log_info("abp_key_init");

    memset(&auth_info, 0x0, sizeof(aliot_gw_auth_info_t));
    ret = aliot_gw_get_auth_info(&auth_info);
    if (0 != ret) {
        log_err("call gateway get auth info api error!");
        return -1;
    }
    memset(dev_key, 0, sizeof(dev_key));
    strncpy((char *)dev_key, auth_info.device_secret, 16);
    //log_info("dev_key: %s", dev_key);

    ret = aliot_gw_get_device_info(&dev_info);
    if (0 != ret) {
        strncpy(eui_h_str, dev_info.gateway_eui, 8);
        strncpy(eui_l_str, dev_info.gateway_eui + 8, 8);
        util_strtol(eui_h_str, &gw_eui_h);
        util_strtol(eui_l_str, &gw_eui_l);
    }

    #if defined(ENABLE_ADVANCED_SECURITY)
    ret = kc_init();
    if (ret) {
        log_err("kc init failed, ret:0x%x", ret);
        return -1;
    }

    ret = kc_add_global_item(key_name, dev_key, strlen((char*)dev_key), key_type);
    if (ret) {
        log_err("kc add item failed, ret:0x%x", ret);
        kc_destroy();
        return -1;
    }

    key_type = 0;
    out_buf_len = 16;
    ret = kc_get_global_item(key_name, out_buf, &out_buf_len, &key_type);
    if (ret != KC_SUCCESS || key_type != KEY_CHAIN_USERDATA) {
        log_err("kc get item failed ret: 0x%x, key_type:%d", ret, key_type);
        kc_destroy();
        return -1;
    }
    //log_info("get device key, type: %d, value: %s", key_type, out_buf);    

    kc_destroy();
    #endif

    return 0;
}

