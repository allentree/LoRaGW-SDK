#ifndef _UPDATE_GLOBAL_H_
#define _UPDATE_GLOBAL_H_
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>

#include <pthread.h>

#include "gwiotapi.h"

#if defined(ENABLE_REMOTE_LOG)
#include "log.h"
#else
#include <stdio.h>
#endif


#define UPDATE_TAG "UPDATE"

#ifndef OTA_STORE_DIR
#define OTA_STORE_DIR "/usr/tmp/lora_ota/"
#endif

#define OTA_PACKAGE_NAME "lora_ota.tar.gz"
#define OTA_PACKAGE_SIGN_NAME "sign"
#define OTA_PACKAGE_PUBLIC_KEY_NAME "./publicKey.pem"
#define OTA_UPDATE_SHELL "update.sh"
#define OTA_UPDATE_ROLLBACK_SHELL "update_rollback.sh"
#define OTA_UPDATE_DONE_SHELL "update_done.sh"
#define OTA_UPDATE_INFO "update.json"
//#define OTA_UPDATE_SHELL "update_done.sh"

#define OAT_STATE_FILE_IDLE ".update_idle"
#define OAT_STATE_FILE_DL ".update_downloading"
#define OAT_STATE_FILE_VERIFING ".update_verifing"
#define OAT_STATE_FILE_WRITTING ".update_writting"
#define OAT_STATE_FILE_CHECKING ".update_checking"
#define OAT_STATE_FILE_DONE ".update_done"

#define OTA_SELF_CHECKING_MAX_WAIT_TIME 300

#if defined(ENABLE_REMOTE_LOG)
#define log_info(fmt, ...)  log_i(UPDATE_TAG, fmt"\n", ##__VA_ARGS__)
#define log_err(fmt, ...)   log_e(UPDATE_TAG, fmt"\n", ##__VA_ARGS__)
#define log_fatal(fmt, ...) log_f(UPDATE_TAG, fmt"\n", ##__VA_ARGS__)
#define log_warn(fmt, ...) log_w(UPDATE_TAG, fmt"\n", ##__VA_ARGS__)
#define log_debug(fmt, ...) log_d(UPDATE_TAG, fmt"\n", ##__VA_ARGS__)

#else
#define log_info(fmt, args...)  \
    do { \
        printf(UPDATE_TAG, "INFO: %s|%03d :: ", __func__, __LINE__); \
        printf(fmt, ##args); \
        printf("%s", "\n"); \
    } while(0)

#define log_err(fmt, args...)  \
        do { \
            printf(UPDATE_TAG, "ERR: %s|%03d :: ", __func__, __LINE__); \
            printf(fmt, ##args); \
            printf("%s", "\n"); \
        } while(0)

#define log_fatal(fmt, args...)  \
    do { \
        printf(UPDATE_TAG, "FATAL: %s|%03d :: ", __func__, __LINE__); \
        printf(fmt, ##args); \
        printf("%s", "\n"); \
    } while(0)

#define log_warn(fmt, args...)  \
        do { \
            printf(UPDATE_TAG, "WARN: %s|%03d :: ", __func__, __LINE__); \
            printf(fmt, ##args); \
            printf("%s", "\n"); \
        } while(0)
#define log_debug(fmt, args...)  \
    do { \
        printf(UPDATE_TAG, "DEBUG: %s|%03d :: ", __func__, __LINE__); \
        printf(fmt, ##args); \
        printf("%s", "\n"); \
    } while(0)

#endif


typedef enum{
 OTA_STATE_IDLE = 0,
 OTA_STATE_DOWNLOADING,
 OTA_STATE_VERIFIING,
 OTA_STATE_WRITTING,
 OTA_STATE_CHECKING,
 OTA_STATE_DONE,
 OTA_STATE_MAX,
}oat_state_et;

typedef struct{
    const char *package_path;

    const char *sign_path;
    
    const char *ota_file_path;

    const char *ota_update;
    const char *ota_rollback;
    const char *ota_update_done;
    
    const char *ota_info_path;
}ota_package_st;

typedef struct{
    char * ver;
    char * md5;
    int fileSize;
}ota_download_info_st;

typedef struct{
    char *current_ver;
    char *manufacturer;
    char *hw_version;
    char *sw_version;
    char *depend_version;
}ota_update_info_st;

typedef struct{
    int check_time;
    int pktfwd_check_state;
    int mqtt_check_state;
    int monitor_check_state;
}ota_update_check_st;

typedef struct{
    ota_package_st ota_package;
    pthread_mutex_t lock;
    aliot_gw_device_info_t dev_info;
	char * cur_ota_ver;
    ota_update_info_st ota_info;

    ota_download_info_st ota_download_info;

    int is_ota_file_checked;

    int sign_valid;
    
    int sh_valid;

    int ver_valid;
    
    int ver_reported;
    int enable_multi_rootfs;

    char public_key_path[FILENAME_MAX + 1];

    ota_update_check_st ota_check;

    oat_state_et ota_state;
}update_global_st;
#endif