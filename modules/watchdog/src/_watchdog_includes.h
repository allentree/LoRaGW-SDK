/*
 * _watchdog_includes.h
 *
 *  Created on: 2017年11月10日
 *      Author: Zhongyang
 */

#ifndef MODULES_WATCHDOG__WATCHDOG_INCLUDES_H_
#define MODULES_WATCHDOG__WATCHDOG_INCLUDES_H_

#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>

// make sure gateway tool-chain uses c style linkage.
#ifdef __cplusplus
extern "C" {
#endif

#if defined(ENABLE_REMOTE_LOG)
#include "log.h"
#else
#include <stdio.h>
#endif

#include "linux-list.h"
#include "dbus/dbus.h"
#include "cJSON.h"
#include "thread_pool.h"

#ifdef __cplusplus
}
#endif

#define WATCHDOG_RESTART_BY_DBUS
// #define WATCHDOG_RESTART_BY_PID

#if !defined WATCHDOG_RESTART_BY_DBUS && !defined WATCHDOG_RESTART_BY_PID
    #error Watchdog restart service should use either dbus or pid
#endif

#if defined WATCHDOG_RESTART_BY_PID
    #error Restart service by PID has not been implement yet.
#endif

#define WATCHDOG_TAG "WATCHDOG"

#if defined(ENABLE_REMOTE_LOG)
#define log_info(fmt, ...)  log_i(WATCHDOG_TAG, fmt"\n", ##__VA_ARGS__)
#define log_err(fmt, ...)   log_e(WATCHDOG_TAG, fmt"\n", ##__VA_ARGS__)
#define log_fatal(fmt, ...) log_f(WATCHDOG_TAG, fmt"\n", ##__VA_ARGS__)
#define log_warn(fmt, ...) log_w(WATCHDOG_TAG, fmt"\n", ##__VA_ARGS__)
#define log_debug(fmt, ...) log_d(WATCHDOG_TAG, fmt"\n", ##__VA_ARGS__)

#else
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

#define log_fatal(fmt, args...)  \
    do { \
        printf("FATAL: %s|%03d :: ", __func__, __LINE__); \
        printf(fmt, ##args); \
        printf("%s", "\n"); \
    } while(0)

#define log_warn(fmt, args...)  \
        do { \
            printf("WARN: %s|%03d :: ", __func__, __LINE__); \
            printf(fmt, ##args); \
            printf("%s", "\n"); \
        } while(0)
#define log_debug(fmt, args...)  \
    do { \
        printf("DEBUG: %s|%03d :: ", __func__, __LINE__); \
        printf(fmt, ##args); \
        printf("%s", "\n"); \
    } while(0)

#endif

extern int32_t g_signal_require_exit;

#include "watchdog_dbus_config.h"
#include "_watchdog_macros.h"
#include "_watchdog_structs.h"
#include "_watchdog_crc32.h"
#include "_watchdog_job_mgmt.h"
#include "_watchdog_job_storage.h"
#include "_watchdog_dbus.h"

#endif /* MODULES_WATCHDOG__WATCHDOG_INCLUDES_H_ */
