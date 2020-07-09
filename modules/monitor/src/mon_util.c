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

#include <limits.h>
#include <errno.h>
#include <arpa/inet.h>
#include "hiredis/hiredis.h"
#include "monitor.h"
#include "monitor_interface_export.h"
#include "monitor_ipc_local.h"


#define UPTIME_FILE  "/proc/uptime"
int mon_util_get_uptime(double *up)
{
    FILE *fp;
    char buf[64];
    double idle = 0;

    fp = fopen(UPTIME_FILE, "r");

    if (fp == NULL) {
        log_err("fail to open %s", UPTIME_FILE);
        return -1;
    }

    if (fgets(buf, sizeof(buf), fp) == NULL) {
        perror("fgets");
        fclose(fp);
        return -1;
    }

    if (sscanf(buf, "%lf %lf", up, &idle) < 2) {
        log_err("fail to sscanf");
        fclose(fp);
        return -1;
    }

    fclose(fp);

    return 0;
}

static int mon_util_add_json(char **p, int *len, char *str)
{
    if (*len <= 0) {
        return -1;
    }

    strncpy(*p, str, *len);

    *len -= strlen(*p);
    *p += strlen(*p);

    return 0;
}

static int mon_util_add_json_str(char **p, int *len, char *key, char *val, int first)
{
    if (*len <= 0) {
        return -1;
    }

    if (first) {
        snprintf(*p, *len, "\"%s\":\"%s\"", key, val);
    } else {
        snprintf(*p, *len, ",\"%s\":\"%s\"", key, val);
    }

    *len -= strlen(*p);
    *p += strlen(*p);

    return 0;
}

static int mon_util_add_json_int(char **p, int *len, char *key, int val, int first)
{
    if (*len <= 0) {
        return -1;
    }

    /* if val abnormal, ignore it */
    if (val < 0) {
        return 0;
    }

    if (first) {
        snprintf(*p, *len, "\"%s\":%d", key, val);
    } else {
        snprintf(*p, *len, ",\"%s\":%d", key, val);
    }

    *len -= strlen(*p);
    *p += strlen(*p);

    return 0;
}

static int mon_util_add_json_long(char **p, int *len, char *key, unsigned long long val, int first)
{
    if (*len <= 0) {
        return -1;
    }

    /* if val abnormal, ignore it */
    if (val == 0) {
        return 0;
    }

    if (first) {
        snprintf(*p, *len, "\"%s\":%llu", key, val);
    } else {
        snprintf(*p, *len, ",\"%s\":%llu", key, val);
    }

    *len -= strlen(*p);
    *p += strlen(*p);

    return 0;
}

static int mon_util_add_json_double(char **p, int *len, char *key, double val)
{
    if (*len <= 0) {
        return -1;
    }

    /* if val abnormal, ignore it */
    if (val <= 0.0) {
        return 0;
    }

    snprintf(*p, *len, ",\"%s\":%.2f", key, val);
    *len -= strlen(*p);
    *p += strlen(*p);

    return 0;
}

int mon_util_gene_json(mon_cb_param_t *param, char *msg, int msg_payload_len)
{
    int i;
    int ret;
    int left_len = msg_payload_len;
    char *p;

    memset(msg, '\0', msg_payload_len);
    p = msg;

    /* add header */
    ret = mon_util_add_json(&p, &left_len, "{\"trap\":{\"sys\":{");

    if (ret < 0) {
        return -1;
    }

    /* add filesystem */
    ret = mon_util_add_json(&p, &left_len, "\"fs\":[");

    if (ret < 0) {
        return -1;
    }

    for (i = 0; i < param->mon_sys.fs_cnt; i++) {

        if (i != 0) {
            ret = mon_util_add_json(&p, &left_len, ",{");
        } else {
            ret = mon_util_add_json(&p, &left_len, "{");
        }

        if (ret < 0) {
            return -1;
        }

        ret = mon_util_add_json_str(&p, &left_len,
                                    "name", param->mon_sys.fs[i].fs_name, 1);

        if (ret < 0) {
            return -1;
        }

        ret = mon_util_add_json_int(&p, &left_len,
                                    "occu", param->mon_sys.fs[i].percent, 0);

        if (ret < 0) {
            return -1;
        }

        if (mon_util_add_json(&p, &left_len, "}") < 0) {
            return -1;
        }
    }

    if (mon_util_add_json(&p, &left_len, "]") < 0) {
        return -1;
    }

    /* add cpu */
    ret = mon_util_add_json_double(&p, &left_len, "cpu",
                                   param->mon_sys.cpu);

    if (ret < 0) {
        return -1;
    }

    /* add memory */
    ret = mon_util_add_json_double(&p, &left_len, "mem",
                                   param->mon_sys.memory);

    if (ret < 0) {
        return -1;
    }

    /* add uptime */
    ret = mon_util_add_json_double(&p, &left_len, "uptime",
                                   param->mon_sys.uptime);

    if (ret < 0) {
        return -1;
    }

    /* add power info */
    ret = mon_util_add_json_int(&p, &left_len, "power",
                                param->mon_sys.power, 0);

    if (ret < 0) {
        return -1;
    }

    /* add temp info */
    ret = mon_util_add_json_int(&p, &left_len, "temp",
                                param->mon_sys.temp, 0);

    if (ret < 0) {
        return -1;
    }

    /* add ping average rtt info */
    ret = mon_util_add_json_double(&p, &left_len, "rtt",
                                   param->mon_sys.avg_rtt);

    if (ret < 0) {
        return -1;
    }

    /* add sys end */
    ret = mon_util_add_json(&p, &left_len, "}");

    if (ret < 0) {
        return -1;
    }

#ifdef MONITOR_SYS_ABP_NS
    /* add abp ns begin */
    ret = mon_util_add_json(&p, &left_len, ",\"abp_ns\":{");
    if (ret < 0) {
        return -1;
    }

    /* add abp ns maxinum info */
    ret = mon_util_add_json_int(&p, &left_len, "maxi",
                                param->mon_sys.nodes_limit, 1);
    if (ret < 0) {
        return -1;
    }

    /* add abp ns stat info */
    ret = mon_util_add_json_int(&p, &left_len, "stat",
                                param->mon_sys.abp_ns_stat, 0);
    if (ret < 0) {
        return -1;
    }

    /* add abp ns end */
    ret = mon_util_add_json(&p, &left_len, "}");
    if (ret < 0) {
        return -1;
    }
#endif

    /* add backhaul dev info */
    ret = mon_util_add_json(&p, &left_len, ",\"net\":[");

    if (ret < 0) {
        return -1;
    }

    for (i = 0; i < MAX_BH_DEV_CNT; i++) {
        if (param->mon_bh_dev[i].type != 0) {

            if (i == 0) {
                ret = mon_util_add_json(&p, &left_len, "{");
            } else {
                ret = mon_util_add_json(&p, &left_len, ",{");
            }

            if (ret < 0) {
                return -1;
            }

            ret = mon_util_add_json_int(&p, &left_len, "type",
                                        param->mon_bh_dev[i].type, 1);

            if (ret < 0) {
                return -1;
            }

            ret = mon_util_add_json_str(&p, &left_len, "ip",
                                        param->mon_bh_dev[i].ipaddr, 0);

            if (ret < 0) {
                return -1;
            }

            ret = mon_util_add_json_long(&p, &left_len, "txbyte",
                                         param->mon_bh_dev[i].tx_bytes, 0);

            if (ret < 0) {
                return -1;
            }

            ret = mon_util_add_json_long(&p, &left_len, "rxbyte",
                                         param->mon_bh_dev[i].rx_bytes, 0);

            if (ret < 0) {
                return -1;
            }

            ret = mon_util_add_json_long(&p, &left_len, "txpacket",
                                         param->mon_bh_dev[i].tx_packets, 0);

            if (ret < 0) {
                return -1;
            }

            ret = mon_util_add_json_long(&p, &left_len, "rxpacket",
                                         param->mon_bh_dev[i].rx_packets, 0);

            if (ret < 0) {
                return -1;
            }

            ret = mon_util_add_json_double(&p, &left_len, "txrate",
                                           param->mon_bh_dev[i].tx_bitrate);

            if (ret < 0) {
                return -1;
            }

            ret = mon_util_add_json_double(&p, &left_len, "rxrate",
                                           param->mon_bh_dev[i].rx_bitrate);

            if (ret < 0) {
                return -1;
            }

            ret = mon_util_add_json(&p, &left_len, "}");

            if (ret < 0) {
                return -1;
            }
        }
    }

    ret = mon_util_add_json(&p, &left_len, "]");

    if (ret < 0) {
        return -1;
    }

    /* add tail */
    ret = mon_util_add_json(&p, &left_len, "}}");

    if (ret < 0) {
        return -1;
    }

    log_dbg("json payload is: %s", msg);
    return 0;
}

#ifdef MONITOR_SYS_ABP_NS
static redisContext *redis_ctx = NULL;
int mon_util_redis_connect(void)
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

int mon_util_redis_disconnect(void)
{
    if (redis_ctx) {
        redisFree(redis_ctx);
        redis_ctx = NULL;
    }

    return 0;
}

int mon_util_redis_set(const char *key, const char *value)
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

    log_info("mon_util_redis_set key:%s", key);

    reply = redisCommand(redis_ctx, "SET %s %s", key, value);
    if (reply != NULL) {
        log_info("reply: %s", reply->str);
        freeReplyObject(reply);
    }

    return 0;
}

int mon_util_redis_get(const char *key, char *value, uint32_t size)
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

    log_info("mon_util_redis_get key:%s", key);

    reply = redisCommand(redis_ctx, "GET %s", key);
    if (reply != NULL) {
        if (reply->str != NULL) {
            log_info("reply: %s", reply->str);
            strncpy(value, reply->str, size);
            value[size] = 0;
        }
        freeReplyObject(reply);
    }

    return 0;
}
#endif

