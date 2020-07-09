#ifndef _MQTT_GLOBAL_H_
#define _MQTT_GLOBAL_H_
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#if defined(ENABLE_REMOTE_LOG)
#include "log.h"
#endif

#include "gwiotapi.h"
typedef struct {
    aliot_gw_auth_info_t auth_info;
    void *pclient;
    void *h_ota;
    void *log_mutex;
    void *check_mutex;
    void *ota_mutex;

    void *abp_mutex;
    int sock_up;
    int sock_down;
    int native_sock_up;
    int native_sock_down;
    int uploadlog_flag;
    int abpdl_flag;
    int checkCnt;
    char *ppub_msg;
    char *prev_msg;
    char *ptpc_gwmp_dl;
    char *ptpc_custom_dl;
    char *ptpc_gwconf_dl;
    char *ptpc_gwconf_get;
    char *ptpc_devinfo_get;
    char *ptpc_gw_reset;
    char *ptpc_log_upload;
    char *ptpc_ctrl_ssh;
    char *ptpc_ctrl_uart;
    char *ptpc_log_upload_user;
    char *ptpc_ctrl_ssh_user;
    char *ptpc_ctrl_uart_user;
} iotx_lorogw_t;


#if defined(ENABLE_REMOTE_LOG)
#define FILELOG_MOD_IOTX         "iotx"
#define FILELOG_MOD_PKFWD        "pktfwd"

#define log_info(fmt, ...)  log_i(NULL, fmt"\n", ##__VA_ARGS__);
#define log_err(fmt, ...)   log_e(NULL, fmt"\n", ##__VA_ARGS__);
#define log_debug(fmt, ...)   log_d(NULL, fmt"\n", ##__VA_ARGS__);
#define log_warning(fmt, ...)   log_w(NULL, fmt"\n", ##__VA_ARGS__);

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

#define log_warning(fmt, args...)  \
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

#endif
