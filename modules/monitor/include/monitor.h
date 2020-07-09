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

#ifndef _MONITOR_H_
#define _MONITOR_H_

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <netinet/in.h>

#if defined(ENABLE_REMOTE_LOG)
#include "log.h"
#define log_dbg(fmt, ...)   log_d(NULL, fmt"\n", ##__VA_ARGS__);
#define log_info(fmt, ...)  log_i(NULL, fmt"\n", ##__VA_ARGS__);
#define log_err(fmt, ...)   log_e(NULL, fmt"\n", ##__VA_ARGS__);
#else

#define log_dbg(fmt, args...)  \
    do { \
        printf("DBG: %s|%03d :: ", __func__, __LINE__); \
        printf(fmt, ##args); \
        printf("%s", "\n"); \
    } while(0)

#define log_info(fmt, args...)  \
    do { \
        printf("INFO: %s|%03d :: ", __func__, __LINE__); \
        printf(fmt, ##args); \
        printf("%s", "\n"); \
    } while(0)

#define log_err(fmt, args...)  \
    do { \
        printf("ERR: %s|%03d :: ", __func__, __LINE__); \
        printf(fmt, ##args); \
        printf("%s", "\n"); \
    } while(0)

#endif

#define MAX_BH_DEV_CNT (2)
#define MAX_BH_TYPE_LEN (32)

typedef enum {
    MON_TYPE_4G = 1,
    MON_TYPE_ETHERNET
} mon_type_t;

typedef struct {
    mon_type_t type;
    char type_name[MAX_BH_TYPE_LEN];
    char name[IFNAMSIZ];
    char ipaddr[INET_ADDRSTRLEN];
    unsigned long long rx_packets;
    unsigned long long tx_packets;
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
    double rx_bitrate;
    double tx_bitrate;
} mon_bh_dev_t;

#define MAX_FS_MOUNT_POINT_CNT (4)
#define MAX_FS_MOUNT_POINT_LEN (32)

typedef struct {
    char fs_name[MAX_FS_MOUNT_POINT_LEN];
    int percent;
} mon_fs_t;

typedef struct {
    int fs_cnt;
    mon_fs_t fs[MAX_FS_MOUNT_POINT_CNT];
    double cpu;
    double memory;
    double uptime;
    double temp;
    int power;
    double avg_rtt;
    int abp_ns_stat;
    int nodes_limit;
} mon_sys_t;

/* file system check callback report operation */
typedef enum {
    MON_SYS_FS = 0,
    MON_SYS_CPU,
    MON_SYS_MEM,
    MON_SYS_UPTIME,
    MON_SYS_TEMP,
    MON_SYS_BAT,
    MON_SYS_ABP_NS,
    MON_BH_TYPE,
    MON_BH_IP,
    MON_BH_TRAFFIC,
    MON_BH_BITRATE,
    MON_BH_PING,
    MON_DMESG,
    MON_MAX
} mon_id_t;

/* monitor callback parameters */
typedef struct {
    mon_id_t mon_id;
    mon_sys_t mon_sys;
    mon_bh_dev_t mon_bh_dev[MAX_BH_DEV_CNT];
} mon_cb_param_t;

typedef int (*mon_func_t)(mon_cb_param_t *param);
int mon_reg_cb(mon_id_t id, mon_func_t mon_func);
int mon_get_cnt(void);

int mon_util_get_uptime(double *up);



int mon_util_gene_json(mon_cb_param_t *param, char *msg, int msg_payload_len);

#ifdef MONITOR_SYS_ABP_NS
int mon_util_redis_connect(void);
int mon_util_redis_disconnect(void);
int mon_util_redis_get(const char *key, char *value, uint32_t size);
#endif

#define __init_call     __attribute__ ((unused,__section__ ("initcall")))

#endif
