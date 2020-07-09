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

#include <getopt.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>
#include "monitor.h"
#include "monitor_ipc_local.h"
#include "monitor_interface_export.h"

#ifdef LORAGW_WATCHDOG_ENABLED
#include "watch_dog_export.h"
#endif
#define MON_VERSION "0.1"

typedef struct {
    mon_id_t mon_id;
    mon_func_t mon_func;
} mon_obj_hdl_t;

static mon_obj_hdl_t *g_mon_obj_hdl_tbl;
static mon_cb_param_t g_mon_cb_param;

static int exit_sig = 0;
static int g_mon_cnt = 0;

static void mon_show_usage(void)
{
    printf(
        "Usage: monitor [OPTIONS]\n\n"
        "  -h, --help                      Show help info\n"
        "  -v, --version                   Display version\n"
    );
}

static struct option arg_options[] = {
    {"version",     no_argument,            0, 'v'},
    {"help",        no_argument,            0, 'h'},
    {0, 0, 0, 0}
};

static pthread_t thrid_mon;
//static pthread_t thrid_alarm;

static int mon_init_cb(void)
{
    int i;

    g_mon_obj_hdl_tbl = malloc(sizeof(mon_obj_hdl_t) * MON_MAX);

    if (g_mon_obj_hdl_tbl == NULL) {
        log_err("malloc failed!");
        return -1;
    }

    memset(g_mon_obj_hdl_tbl, '\0', sizeof(mon_obj_hdl_t) * MON_MAX);

    for (i = 0; i < MON_MAX; i++) {
        g_mon_obj_hdl_tbl[i].mon_id = i;
    }

    return 0;
}

static int mon_exec_cb(void)
{
    int i;
    int ret;

    for (i = 0; i < MON_MAX; i++) {

        if (g_mon_obj_hdl_tbl[i].mon_func != NULL) {
            g_mon_cb_param.mon_id = i;
            ret = g_mon_obj_hdl_tbl[i].mon_func(&g_mon_cb_param);

            if (ret != 0) {
                log_err("exec func id=%d failed", i);
                continue;
            }
        }

    }

    return 0;
}

#ifdef MON_DUMP_PARAM
static void mon_dump_param(mon_cb_param_t *param)
{
    int i;

    printf("monitor result dump:\n");

    for (i = 0; i < param->mon_sys.fs_cnt; i++) {
        printf("filesystem mount point: %s usage: %d %%\n",
               param->mon_sys.fs[i].fs_name, param->mon_sys.fs[i].percent);
    }

    printf("system uptime is %f s\n", param->mon_sys.uptime);
    printf("power left percent is %d %%\n", param->mon_sys.power);
    printf("CPU temperature is %f C\n", param->mon_sys.temp);
    printf("ping average rtt is %f ms\n", param->mon_sys.avg_rtt);
    printf("system cpu is %f %%\n", param->mon_sys.cpu);
    printf("system memory is %f %%\n", param->mon_sys.memory);
    printf("ping average rtt is %f ms\n", param->mon_sys.avg_rtt);
    return;
}
#endif

#define MAX_PAYLOAD_LEN (1024)

static char g_mon_gwmp[MAX_PAYLOAD_LEN];

static int mon_send_payload(void)
{
    int ret;

    //log_info("mon send msg: %s", g_mon_gwmp);

    ret = monitor_gwmp_msg_send(g_mon_gwmp);

    if (ret < 0) {
        log_err("fail to send gwmp msg");
        return -1;
    }
    else {
        log_info("send gwmp message done!!!");
    }
    return 0;
}

#define MON_THR_ID "thrid_mon"
#ifdef LORAGW_WATCHDOG_ENABLED
static int mon_cancel_watchdog(void)
{
    int ret;

    ret = thread_cancel_feeddog(MONITOR_SYMBOL, MON_THR_ID);

    if (ret != WATCHDOG_SUCCESS) {
        log_err("fail to cancel watchdog, err=%d", ret);
        return -1;
    }

    return 0;
}
#endif
static void sigint_handler(int sig)
{
#ifdef LORAGW_WATCHDOG_ENABLED 
    mon_cancel_watchdog();
#endif    
    
    exit_sig = 1;
    //exit(EXIT_FAILURE);
}

#ifdef LORAGW_WATCHDOG_ENABLED
static int mon_feed_watchdog(void)
{
    int ret;

    ret = thread_feeddog(MONITOR_SYMBOL, MON_THR_ID, MON_INTERVAL + 60);

    if (ret != WATCHDOG_SUCCESS) {
        log_err("fail to feed dog, err=%d", ret);
        return -1;
    }

    return 0;
}
#endif

static void *mon_thread_check(void *arg)
{
    static int check_count = 0;
    static int max_check_cnt = 3;
    static int exception_count = 0;

    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    pthread_sigmask(SIG_UNBLOCK, &mask, &oldmask);

    while (!exit_sig) {
        memset(&g_mon_cb_param, '\0', sizeof(g_mon_cb_param));
        g_mon_cnt++;
        mon_exec_cb();
#ifdef LORAGW_WATCHDOG_ENABLED
        mon_feed_watchdog();
#endif
#ifdef MON_DUMP_PARAM
        mon_dump_param(&g_mon_cb_param);
#endif
        check_count ++;
#ifdef ENABLE_ADVANCED_OTA
        if(g_mon_cb_param.mon_sys.cpu > 80.0 || g_mon_cb_param.mon_sys.memory > 80.0 ) {
            exception_count ++;
        }
        if(MON_INTERVAL > 300) {
            max_check_cnt = 0;
        } else {
            max_check_cnt = (300 / MON_INTERVAL) - 1;
        }
        if(check_count > max_check_cnt && !exception_count) {
            monitor_notify_update_checkout_result(0, "system state is OK");
        }
#endif
        int ret;
        ret = mon_util_gene_json(&g_mon_cb_param, g_mon_gwmp, MAX_PAYLOAD_LEN);

        if (ret < 0) {
            log_err("fail to generate json!");
            continue;
        }

        mon_send_payload();

        sleep(MON_INTERVAL);
    }

    return NULL;
}


static int mon_create_thread(void)
{
    int ret;

    ret = pthread_create(&thrid_mon, NULL, mon_thread_check, NULL);

    if (ret != 0) {
        log_err("create monitor thread failed!");
        return -1;
    }

    ret = monitor_dbus_setup();
    if(ret < 0) {
        log_err("create ipc interface failed!");
        exit_sig = 1;
        pthread_join(thrid_mon, NULL);
        return -1;
    }
    return 0;
}

extern void *__start_initcall;
extern void *__stop_initcall;

static int mon_init(void)
{
    int ret = 0;

    ret = mon_init_cb();

    if (ret != 0) {
        log_err("mon_init_cb failed!");
        return -1;
    }

    void **ptr;
    int (*mon_func)(void);

    ptr = &__start_initcall;

    while (ptr != &__stop_initcall) {
        mon_func = *ptr++;
        ret = mon_func();

        if (ret != 0) {
            log_err("func init failed!");
            return -1;
        }
    }

    return 0;
}

int mon_reg_cb(mon_id_t id, mon_func_t mon_func)
{

    int i;

    for (i = 0; i < MON_MAX; i++) {
        if (g_mon_obj_hdl_tbl[i].mon_id == id) {
            g_mon_obj_hdl_tbl[i].mon_func = mon_func;
            break;
        }
    }

    if (i == MON_MAX) {
        log_err("id = %d no exsited!", i);
        return -1;
    }

    return 0;
}

int mon_get_cnt(void)
{
    return g_mon_cnt;
}

int main(int argc, char *argv[])
{
    int ret;

    /* get options */
    while (1) {
        int c;
        int option_index = 0;
        c = getopt_long(argc, argv, "vh", arg_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
            case 'h':
                mon_show_usage();
                return 0;

            case 'v':
                printf("monitor version: %s\n", MON_VERSION);
                return 0;

            default:
                mon_show_usage();
                return -1;
        }
    }
#if defined(ENABLE_REMOTE_LOG)
    log_init("MonitorLog", LOG_FILE, LOG_LEVEL_INFO, LOG_MOD_VERBOSE);
    log_file_init("MonitorLog", 5 , 1);
#endif
    ret = mon_init();

    if (ret != 0) {
        log_err("mon_init failed!");
        return -1;
    }

    signal(SIGINT, sigint_handler);

    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

    ret = mon_create_thread();

    if (ret != 0) {
        return -1;
    }
#if defined(LORAGW_WATCHDOG_ENABLED)
	struct timespec watchdog_time_keeper;
	clock_gettime(CLOCK_MONOTONIC, &watchdog_time_keeper);
#endif
    while(!exit_sig) {
        sleep(5);
#if defined(LORAGW_WATCHDOG_ENABLED)
        thread_feeddog_periodically(MONITOR_SYMBOL, "main_thread", 60, 120, &watchdog_time_keeper);
#endif

    }
    pthread_join(thrid_mon, NULL);

    monitor_dbus_exit();
    //pthread_join(thrid_alarm, NULL);

    return 0;
}
