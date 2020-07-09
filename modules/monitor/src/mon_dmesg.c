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
#include <sys/klog.h>
#include <sys/syslog.h>
#include <stdlib.h>
#include "monitor.h"
#include "monitor_interface_export.h"
#include "monitor_ipc_local.h"

/* Read all messages remaining in the ring buffer. (allowed for non-root) */
#define SYSLOG_ACTION_READ_ALL       3

/* Return size of the log buffer */
#define SYSLOG_ACTION_SIZE_BUFFER   10

#define MAX_DMESG_LOG_LEN (16 * 1024)

static int mon_dmesg_get_buf(char **buf)
{
    int len;

    len = klogctl(SYSLOG_ACTION_SIZE_BUFFER, NULL, 0);

    if (len < 0) {
        perror("klogctl");
        return -1;
    } else if (len < 1024) {
        len = 1024;
    } else if (len > MAX_DMESG_LOG_LEN) {
        len = MAX_DMESG_LOG_LEN;
    }

    *buf = malloc(len);

    if (*buf == NULL) {
        log_err("malloc");
        return -1;
    }

    len = klogctl(SYSLOG_ACTION_READ_ALL, *buf, len);

    if (len < 0) {
        free(*buf);
        perror("klogctl");
        return -1;
    } else if (len == 0) {
        log_info("no kmsg");
        return 0;
    }

    if ((*buf)[len - 1] == '\n') {
        (*buf)[len - 1] = '\0';
    }

    return 0;
}

static int mon_dmesg_get_result(char *buf, char *result, int max_len)
{
    int ret = 0;
    const char *delim = "\n";
    char *token;
    char *cur = buf;
    double time;
    double pre_log_time;
    int log_level;
    int total_sz = 0;

    ret = mon_util_get_uptime(&pre_log_time);

    if (ret != 0) {
        log_err("fail!");
        return -1;
    }

    pre_log_time -= MON_INTERVAL;

    while ((token = strsep(&cur, delim))) {

        if (sscanf(token, "<%d>[%lf]", &log_level, &time) < 2) {
            log_info("sscanf fail, str=%s", token);
            continue;
        }

        if (log_level >= LOG_WARNING || time < pre_log_time) {
            continue;
        }

        log_dbg("log level=%d, time=%lf, line=%s", log_level, time, token);

        total_sz += strlen(token);

        if (total_sz >= max_len) {
            log_info("no enough space left for dmesg");
            break;
        }

        strncat(result, token, strlen(token));
        ret = 1;
    }

    return ret;
}

static int mon_dmesg_check(mon_cb_param_t *param)
{
    int ret;
    char *buf;
    char result[MAX_ALARM_PAYLOAD_LEN] = {'\0'};

    ret = mon_dmesg_get_buf(&buf);

    if (ret != 0) {
        log_err("fail!");
        return -1;
    }

    ret = mon_dmesg_get_result(buf, result, sizeof(result));

    if (ret == -1) {
        free(buf);
        log_err("fail!");
        return -1;
    }

    free(buf);

    if (ret == 0) {
        log_dbg("no dmesg error");
    } else {
        log_dbg("dmesg is %s", result);
        if(monitor_send_alarm_interal(MON_ALARM_DMESG, result) < 0) {
            log_err("send alarm signal to monitor failed!!!");
        }
    }

    return 0;
}

static int mon_dmesg_init(void)
{
    log_dbg("init start");
    mon_reg_cb(MON_DMESG, mon_dmesg_check);
    return 0;
}

static int (*_mon_dmesg_init)(void) __init_call = mon_dmesg_init;
