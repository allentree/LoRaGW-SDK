/*
 * Copyright (c) 2014-2017 Alibaba Group. All rights reserved.
 *
 * Alibaba Group retains all right, title and interest (including all
 * intellectual property rights) in and to this computer program, which is
 * protected by applicable intellectual property laws.  Unless you have
 * obtained a separate written license from Alibaba Group., you are not
 * authorized to utilize all or a part of this computer program for any
 * purpose (including reproduction, distribution, modification, and
 * compilation into object code), and you must immediately destroy or
 * return to Alibaba Group all copies of this computer program.  If you
 * are licensed by Alibaba Group, your rights to utilize this computer
 * program are limited by the terms of that license.  To obtain a license,
 * please contact Alibaba Group.
 *
 * This computer program contains trade secrets owned by Alibaba Group.
 * and, unless unauthorized by Alibaba Group in writing, you agree to
 * maintain the confidentiality of this computer program and related
 * information and to not disclose this computer program and related
 * information to any other person or entity.
 *
 * THIS COMPUTER PROGRAM IS PROVIDED AS IS WITHOUT ANY WARRANTIES, AND
 * Alibaba Group EXPRESSLY DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED,
 * INCLUDING THE WARRANTIES OF MERCHANTIBILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, TITLE, AND NONINFRINGEMENT.
 */
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/select.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#include "iot_import.h"
#include "iot_export.h"

#include "mqtt_global.h"

#include "gwiotapi.h"
#include "sysconfig.h"
#include "abp_nodes.h"

#if defined(ENABLE_WATCHDOG)
#include "watch_dog_export.h"
#endif

#include "mqtt_ipc_local.h"

#if defined(ENABLE_MONITOR)
#include <limits.h>
#define CUSTOM_MON_MSG_UP_ID            0xA0
#define CUSTOM_MON_MSG_DOWN_ID          0xA1
#include "monitor_interface_export.h"
#endif

//#define ENABLE_MSG_CACHE 
#if defined(ENABLE_MSG_CACHE)
#include "msg/utils_msg.h"
#endif

#if defined(ENABLE_ABP_NODES)
static int lora_ns_server_exist = 0;
#endif

#define ENABLE_OTA
#define ENABLE_REMOTE_CTRL_SSH
#define ENABLE_REMOTE_CTRL_UART

#define TOPIC_GWMP_UPLINK        "/lora/gwmp/uplink"
#define TOPIC_GWMP_DOWNLINK      "/lora/gwmp/downlink"
#define TOPIC_CUSTOM_UPLINK      "/lora/custom/uplink"
#define TOPIC_CUSTOM_DOWNLINK    "/lora/custom/downlink"
#define TOPIC_GWCONFIG_UPLOAD    "/lora/gwconfig/upload"
#define TOPIC_GWCONFIG_DOWNLOAD  "/lora/gwconfig/download"
#define TOPIC_GWCONFIG_GET       "/lora/gwconfig/get"
#define TOPIC_DEVICEINFO_UPLOAD  "/lora/deviceinfo/upload"
#define TOPIC_DEVICEINFO_GET     "/lora/deviceinfo/get"
#define TOPIC_GW_RESET           "/lora/gw/reset"
#define TOPIC_LOG_UPLOAD         "/logfile/upload"
#define TOPIC_CTRL_SSH           "/ctrl/ssh"
#define TOPIC_CTRL_UART          "/ctrl/uart"

#define UDP_LOCALHOST_ADDR       "127.0.0.1"
#define MSG_LEN_MAX              (8 * 1024)
#define TOPIC_NAME_LEN_MAX       128
#define GWMP_HEAD_UP_LEN         12
#define GWMP_HEAD_DOWN_LEN       4
#define OTA_BUF_LEN              (6 * 1024)

#define CUSTOM_MSG_ID            0x80

#if defined(ENABLE_WATCHDOG)
#define THRD_ID_MAIN             "thrd_main"
#define THRD_ID_OTA              "thrd_ota"
#define THRD_ID_UPLINK           "thrd_uplink"
#define THRD_ID_NAT_DOWNLINK     "thrd_nat_downlink"
#endif

#define MQTT_CONNECT_RESET_CHECK_CNT 300

static int exit_sig = 0;
#if defined(ENABLE_MSG_CACHE)
static int enable_cache = 0;
#endif
static int native_exit_sig = 0;

const char uploadDeviceinfo[] = {
    "\"deviceinfo\": {\
\"gateway_eui\": \"%s\",\
\"model\": \"%s\",\
\"manufacturer\": \"%s\",\
\"hw_version\": \"%s\",\
\"sw_version\": \"%s\",\
\"ota_version\": \"%s\"\
}"
};



iotx_lorogw_t g_iotx_loragw;
extern uint8_t abp_out_enable;

#ifdef ENABLE_OTA
#ifdef ENABLE_ADVANCED_OTA
static FILE *testfp = NULL;

static int _ota_download_start(const char *path)
{
    if(!path || strlen(path)== 0)
        return -1;
    testfp = fopen(path, "w");
    if (NULL == testfp) {
        printf("fopen OTA file failed\n");
        return -1;
    }

    return 0;
}


int _ota_download_write(char *buffer, uint32_t length)
{
    uint32_t written_len = 0;

    if (NULL == testfp) {
        printf("OTA file not fopen\n");
        return -1;
    }

    written_len = fwrite(buffer, 1, length, testfp);

    if (written_len != length) {
        printf("fwrite failed, %d != %d\n", written_len, length);
        return -1;
    }
    return 0;
}

static int _ota_download_finalize(int stat)
{
    if (testfp != NULL) {
        fclose(testfp);
        testfp = NULL;
    }
    return 0;
}
#endif
#endif

void event_handle(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    uintptr_t packet_id = (uintptr_t)msg->msg;
    iotx_mqtt_topic_info_pt topic_info = (iotx_mqtt_topic_info_pt)msg->msg;

    switch (msg->event_type) {
        case IOTX_MQTT_EVENT_UNDEF:
            log_info("undefined event occur.");
            break;

        case IOTX_MQTT_EVENT_DISCONNECT:
        #if defined(ENABLE_MSG_CACHE)
            enable_cache = 1;
        #endif    
            log_info("MQTT disconnect.");
            break;

        case IOTX_MQTT_EVENT_RECONNECT:
            log_info("MQTT reconnect.");
            break;

        case IOTX_MQTT_EVENT_SUBCRIBE_SUCCESS:
            log_info("subscribe success, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_SUBCRIBE_TIMEOUT:
            log_info("subscribe wait ack timeout, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_SUBCRIBE_NACK:
            log_info("subscribe nack, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_UNSUBCRIBE_SUCCESS:
            log_info("unsubscribe success, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_UNSUBCRIBE_TIMEOUT:
            log_info("unsubscribe timeout, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_UNSUBCRIBE_NACK:
            log_info("unsubscribe nack, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_PUBLISH_SUCCESS:
        #if defined(ENABLE_MSG_CACHE)
            enable_cache = 0;
        #endif
            log_info("publish success, packet-id=%u checkCnt=%d", (unsigned int)packet_id, ploragw->checkCnt);
            HAL_MutexLock(ploragw->check_mutex);
            ploragw->checkCnt++;
            HAL_MutexUnlock(ploragw->check_mutex);
            break;

        case IOTX_MQTT_EVENT_PUBLISH_TIMEOUT:
            log_info("publish timeout, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_PUBLISH_NACK:
            log_info("publish nack, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_PUBLISH_RECEIVED:
            log_info("topic message arrived but without any related handle: topic=%.*s, topic_msg=%.*s",
                          topic_info->topic_len,
                          topic_info->ptopic,
                          topic_info->payload_len,
                          topic_info->payload);
            break;

        case IOTX_MQTT_EVENT_BUFFER_OVERFLOW:
            log_info("buffer overflow, %s", (char *)(msg->msg));
            break;

        default:
            log_info("Should NOT arrive here.");
            break;
    }
}

void thread_file_check(void)
{
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    int ret = 0;

    while (!exit_sig) {
        #if defined(ENABLE_REMOTE_LOG)
        if (1 == ploragw->uploadlog_flag) {
            log_file_upload(FILELOG_MOD_IOTX, ploragw->auth_info.device_name);
            log_file_upload(FILELOG_MOD_PKFWD, ploragw->auth_info.device_name);

            HAL_MutexLock(ploragw->log_mutex);
            ploragw->uploadlog_flag = 0;
            HAL_MutexUnlock(ploragw->log_mutex);
            log_info("after upload_filelog, set upload log_flag: %d\n", ploragw->uploadlog_flag);
        }
        #endif

        #if defined(ENABLE_ABP_NODES)
        if (1 == ploragw->abpdl_flag) {
            ret = abp_file_download();
            if (0 == ret) {
                abp_send_msg_ack(NULL);
                abp_redis_init();
            } else {
                abp_send_msg_ack("abpf:download error");
            }

            HAL_MutexLock(ploragw->abp_mutex);
            ploragw->abpdl_flag = 0;
            HAL_MutexUnlock(ploragw->abp_mutex);
            log_info("after abp_file_download, set abpdl_flag: %d", ploragw->abpdl_flag);
        }
        #endif

        HAL_SleepMs(1000);
    }

    return;
}

#if defined(ENABLE_OTA)
#ifdef ENABLE_ADVANCED_OTA
int need_reinit_ota = 0;
void thread_ota_check(void)
{
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    char buf_ota[OTA_BUF_LEN] = {0};
    //char cur_ver[64] = {0};
    //char *ota_ver = NULL;
    uint32_t firmware_valid = 0;
    int fin_stat = -1;
    int ret = -1;
    char ota_file_path[FILENAME_MAX + 1]  = { 0 };
    //int reportver = 1;
    #if defined(ENABLE_WATCHDOG)
	struct timespec watchdog_time_keeper;
	clock_gettime(CLOCK_MONOTONIC, &watchdog_time_keeper);
    #endif

    while (!exit_sig) {
        HAL_SleepMs(1000);
        HAL_MutexLock(ploragw->ota_mutex);
        if(need_reinit_ota){
            log_info("reinitialize OTA");
            IOT_OTA_Deinit(ploragw->h_ota);
            ploragw->h_ota = NULL;
            HAL_MutexUnlock(ploragw->ota_mutex);

            HAL_SleepMs(2000);
            
            HAL_MutexLock(ploragw->ota_mutex);
            need_reinit_ota = 0;
            ploragw->h_ota = IOT_OTA_Init(ploragw->auth_info.product_key, ploragw->auth_info.device_name, ploragw->pclient);
            if (NULL == ploragw->h_ota) {
                log_err("initialize OTA failed");
                HAL_MutexUnlock(ploragw->ota_mutex);
                break;
            }
            
        }

        if (IOT_OTA_IsFetching(ploragw->h_ota)) {
            HAL_MutexUnlock(ploragw->ota_mutex);
            uint32_t last_percent = 0, percent = 0;
            uint32_t  size_downloaded = 0, size_file = 0;
            int len = 0;
            char version[32], md5sum[33];

            //get OTA information
            IOT_OTA_Ioctl(ploragw->h_ota, IOT_OTAG_FILE_SIZE, &size_file, 4);
            memset(md5sum, 0x0, sizeof(md5sum));
            IOT_OTA_Ioctl(ploragw->h_ota, IOT_OTAG_MD5SUM, md5sum, 33);
            memset(version, 0x0, sizeof(version));
            IOT_OTA_Ioctl(ploragw->h_ota, IOT_OTAG_VERSION, version, 32);

            log_info("OTA info, new version: %s, md5sum: %s, file size: %d", version, md5sum, size_file);

            if (0 == size_file) {
                log_err("file size is 0, ota failed");
                HAL_SleepMs(2000);
                continue;
            }
            ota_file_path[0] = '\0';
            ret = ota_notify_update_file_info(version, md5sum, size_file, ota_file_path);
            if (LORA_IPC_SUCCESS != ret) {
                log_err("notify update-deamon for downloading failed ret %d !", ret);
                HAL_SleepMs(2000);
                continue;
            }

            ret = _ota_download_start(ota_file_path);
            if(ret < 0) {
                log_err("call ota start api failed");
                HAL_SleepMs(2000);
                continue;
            }
            do {
                len = IOT_OTA_FetchYield(ploragw->h_ota, buf_ota, OTA_BUF_LEN, 1);
                if (len > 0) {
                    ret = _ota_download_write(buf_ota, (uint32_t)len);
                    if (-1 == ret) {
                        log_err("call ota write api failed");
                        break;
                    }
                    log_info("write %d bytes to file %s !\n", len, ota_file_path);
                }
                else {
                    log_err("IOT_OTA_FetchYield error!\n");
                }

                // get downloaded size
                IOT_OTA_Ioctl(ploragw->h_ota, IOT_OTAG_FETCHED_SIZE, &size_downloaded, 4);
                log_info("current download size %d !", size_downloaded);
                percent = (size_downloaded * 50) / size_file;
                if ((percent == 50) || ((percent < 50) && (percent - last_percent >= 10))) {
                    IOT_OTA_ReportProgress(ploragw->h_ota, percent, "");
                    log_info("download percent:%d", percent);
                    last_percent = percent;
                }
                HAL_SleepMs(100);

        #if defined(ENABLE_WATCHDOG)
                if (thread_feeddog_periodically(MQTT_SYMBOL, THRD_ID_OTA, 60, 1200, &watchdog_time_keeper) < 0) {
                    log_err("OTA thread feeddog failed\n");
                }
        #endif

            } while(!IOT_OTA_IsFetchFinish(ploragw->h_ota));

            if(size_downloaded < size_file) {
                log_err("download failed!");
                IOT_OTA_ReportProgress(ploragw->h_ota, IOT_OTAP_CHECK_FALIED, "download failed");
                fin_stat = -1;
            }
            else {
                IOT_OTA_Ioctl(ploragw->h_ota, IOT_OTAG_CHECK_FIRMWARE, &firmware_valid, 4);
                if (0 == firmware_valid) {
                    log_info("The firmware is invalid");
                    IOT_OTA_ReportProgress(ploragw->h_ota, IOT_OTAP_CHECK_FALIED, "check failed");
                    fin_stat = -1;
                } else {
                    log_info("The firmware is valid");

                    fin_stat = 0;

                    HAL_SleepMs(2000);
                }
            }
            
            _ota_download_finalize(fin_stat);

            ret = ota_notify_update_download_result(fin_stat, (int)size_downloaded);
            if(ret < 0) {
                log_err("notify download result failed!!!");
                IOT_OTA_ReportProgress(ploragw->h_ota, IOT_OTAP_GENERAL_FAILED, "notify update-deamon failed");
            }

            if(fin_stat == -1 || ret < 0) {
                log_info("reinitialize OTA");
                HAL_MutexLock(ploragw->ota_mutex);
                IOT_OTA_Deinit(ploragw->h_ota);
                ploragw->h_ota = NULL;
                HAL_MutexUnlock(ploragw->ota_mutex);

                HAL_SleepMs(2000);
                
                HAL_MutexLock(ploragw->ota_mutex);
                ploragw->h_ota = IOT_OTA_Init(ploragw->auth_info.product_key, ploragw->auth_info.device_name, ploragw->pclient);
                if (NULL == ploragw->h_ota) {
                    log_err("initialize OTA failed");
                    HAL_MutexUnlock(ploragw->ota_mutex);
                    break;
                }
                HAL_MutexUnlock(ploragw->ota_mutex);
            }

        }
        else {
            HAL_MutexUnlock(ploragw->ota_mutex);
        }
        
        HAL_SleepMs(2000);

        #if defined(ENABLE_WATCHDOG)
        if (thread_feeddog_periodically(MQTT_SYMBOL, THRD_ID_OTA, 60, 600, &watchdog_time_keeper) < 0) {
            log_err("OTA thread feeddog failed\n");
        }
        #endif
    }

    #if defined(ENABLE_WATCHDOG)
    thread_cancel_feeddog(MQTT_SYMBOL, THRD_ID_OTA);
    #endif

    return;
}
#else 
void thread_ota_check(void)
{
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    char buf_ota[OTA_BUF_LEN] = {0};
    char cur_ver[64] = {0};
    char *ota_ver = NULL;
    uint32_t firmware_valid = 0;
    int fin_stat = -1;
    int ret = -1;
    int reportver = 1;
    #if defined(ENABLE_WATCHDOG)
	struct timespec watchdog_time_keeper;
	clock_gettime(CLOCK_MONOTONIC, &watchdog_time_keeper);
    #endif

    while (!exit_sig) {
        if (1 == reportver) {
            ota_ver = config_get_ota_version();
            if (NULL == ota_ver) {
                log_err("get OTA version failed\n");
                HAL_SleepMs(2000);
                continue;
            }
            
            snprintf(cur_ver, sizeof(cur_ver), "%s", ota_ver);
            ret = IOT_OTA_ReportVersion(ploragw->h_ota, cur_ver);
            if (0 != ret) {
                log_err("report OTA version failed, ret: %d\n", ret);
                HAL_SleepMs(2000);
                continue;
            }

            reportver = 0;
        }

        HAL_SleepMs(1000);
        if (IOT_OTA_IsFetching(ploragw->h_ota)) {
            uint32_t last_percent = 0, percent = 0;
            uint32_t len = 0, size_downloaded = 0, size_file = 0;
            char version[32], md5sum[33];

            //get OTA information
            IOT_OTA_Ioctl(ploragw->h_ota, IOT_OTAG_FILE_SIZE, &size_file, 4);
            memset(md5sum, 0x0, sizeof(md5sum));
            IOT_OTA_Ioctl(ploragw->h_ota, IOT_OTAG_MD5SUM, md5sum, 33);
            memset(version, 0x0, sizeof(version));
            IOT_OTA_Ioctl(ploragw->h_ota, IOT_OTAG_VERSION, version, 32);
            log_info("OTA info, new version: %s, md5sum: %s, file size: %d", version, md5sum, size_file);

            if (0 == size_file) {
                log_err("file size is 0, ota failed");
                HAL_SleepMs(2000);
                continue;
            }
            
            ret = aliot_platform_ota_start(md5sum);
            if (-1 == ret) {
                log_err("call ota start api failed");
                HAL_SleepMs(2000);
                continue;
            }

            do {
                len = IOT_OTA_FetchYield(ploragw->h_ota, buf_ota, OTA_BUF_LEN, 1);
                if (len > 0) {
                    ret = aliot_platform_ota_write(buf_ota, len);
                    if (-1 == ret) {
                        log_err("call ota write api failed");
                        break;
                    }
                }

                // get downloaded size
                IOT_OTA_Ioctl(ploragw->h_ota, IOT_OTAG_FETCHED_SIZE, &size_downloaded, 4);

                percent = (size_downloaded * 100) / size_file;
                if ((percent == 100) || ((percent < 100) && (percent - last_percent >= 10))) {
                    IOT_OTA_ReportProgress(ploragw->h_ota, percent, "");
                    log_info("download percent:%d", percent);
                    last_percent = percent;
                }
                HAL_SleepMs(100);
#if defined(ENABLE_WATCHDOG)
                if (thread_feeddog_periodically(MQTT_SYMBOL, THRD_ID_OTA, 60, 1200, &watchdog_time_keeper) < 0) {
                    log_err("OTA thread feeddog failed\n");
                }
#endif

            } while(!IOT_OTA_IsFetchFinish(ploragw->h_ota));

            IOT_OTA_Ioctl(ploragw->h_ota, IOT_OTAG_CHECK_FIRMWARE, &firmware_valid, 4);
            if (0 == firmware_valid) {
                log_info("The firmware is invalid");
                IOT_OTA_ReportProgress(ploragw->h_ota, IOT_OTAP_CHECK_FALIED, "check failed");
                fin_stat = -1;
            } else {
                log_info("The firmware is valid");

                fin_stat = 0;

                HAL_SleepMs(2000);
            }

            ret = aliot_platform_ota_finalize(fin_stat);
            if (-1 == ret) {
                log_err("call ota finalize api failed");
                IOT_OTA_ReportProgress(ploragw->h_ota, IOT_OTAP_BURN_FAILED, "burn failed");
            } else {
                log_info("report version:%s", version);
                IOT_OTA_ReportVersion(ploragw->h_ota, version);
            }

            log_info("reinitialize OTA");
            IOT_OTA_Deinit(ploragw->h_ota);
            HAL_SleepMs(2000);
            ploragw->h_ota = IOT_OTA_Init(ploragw->auth_info.product_key, ploragw->auth_info.device_name, ploragw->pclient);
            if (NULL == ploragw->h_ota) {
                log_err("initialize OTA failed");
            }
            reportver = 1;
        }

        HAL_SleepMs(2000);

        #if defined(ENABLE_WATCHDOG)
		if (thread_feeddog_periodically(MQTT_SYMBOL, THRD_ID_OTA, 60, 600, &watchdog_time_keeper) < 0) {
			log_err("OTA thread feeddog failed\n");
		}
        #endif
    }

    #if defined(ENABLE_WATCHDOG)
	thread_cancel_feeddog(MQTT_SYMBOL, THRD_ID_OTA);
    #endif

    return;
}
#endif

#endif

#if defined(ENABLE_MSG_CACHE)
static int set_history_msg(const char *msg, uint32_t len)
{
    int ret = 0;
    log_info("store msg to DB.....");
    msg_set(msg, len);
    return ret;
}

static int get_history_msg(char *msg_buf, uint32_t msg_buf_len, uint32_t *msg_len)
{
    int ret = 0;
    ret = msg_get(msg_buf, msg_buf_len, msg_len);

    log_info("get msg from DB,ret=%d.....",ret);
    return ret;

}
#endif

int publish_gwmp_msg_uplink(char *msg_buf, int msg_len)
{
    int ret = -1;
    iotx_mqtt_topic_info_t topic_msg;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    char topicName[TOPIC_NAME_LEN_MAX] = {0};

    memset(&topic_msg, 0x0, sizeof(iotx_mqtt_topic_info_t));
    topic_msg.qos = IOTX_MQTT_QOS1;
    topic_msg.retain = 0;
    topic_msg.dup = 0;
    topic_msg.payload = msg_buf;
    topic_msg.payload_len = msg_len;

    if ((msg_len > 3) && (msg_buf[3] >= CUSTOM_MSG_ID)) {
        snprintf(topicName, sizeof(topicName), "/sys/%s/%s%s", ploragw->auth_info.product_key, ploragw->auth_info.device_name, TOPIC_CUSTOM_UPLINK);
    } else {
        snprintf(topicName, sizeof(topicName), "%s/%s/%s", TOPIC_GWMP_UPLINK, ploragw->auth_info.product_key, ploragw->auth_info.device_name);
    }
    ret = IOT_MQTT_Publish(ploragw->pclient, topicName, &topic_msg);
    if (ret < 0) {
        log_err("IOT_MQTT_Publish failed ret = %d", ret);
    #if defined(ENABLE_MSG_CACHE)    
        enable_cache = 1;
      
        set_history_msg(msg_buf, msg_len);
    #endif  
    }

    if (msg_len > GWMP_HEAD_UP_LEN) {
        log_info("publish mqtt gwmp msg: %s, len: %d\n", msg_buf + GWMP_HEAD_UP_LEN, msg_len);
    } else {
        log_info("publish mqtt gwmp msg len: %d\n", msg_len);
    }
    return ret;
}

#if defined(ENABLE_MSG_CACHE)
void thread_msg_cache(void)
{
    char *pdatabuf = NULL;
    int byte_nb = 0;
    pdatabuf = (char *)HAL_Malloc(MSG_LEN_MAX);

    while (!exit_sig) {
        if (1 == enable_cache) {
            log_info("msg_cache working, decide not to get msg from DB");
            HAL_SleepMs(60000);
            continue;
        }

        log_info("msg_cache not working, begin to get history msg from DB.");
        if(get_history_msg(pdatabuf, MSG_LEN_MAX, (uint32_t *)&byte_nb) >= 0) {
            publish_gwmp_msg_uplink(pdatabuf, byte_nb);
            log_info("pub history msg cached in DB, msg_lenth=%d", byte_nb);
        } else {
            log_info("no history msg in DB!!!");
            HAL_SleepMs(60000);
        }
        HAL_SleepMs(500);
    }
    
    HAL_Free(pdatabuf);
    return;
}
#endif

int publish_gwconfig_upload(void)
{
    int ret = -1;
    iotx_mqtt_topic_info_t topic_msg;
    int data_len = 0;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    char topicName[TOPIC_NAME_LEN_MAX] = {0};

    memset(ploragw->ppub_msg, 0x0, MSG_LEN_MAX);
    data_len = aliot_gw_get_global_conf((unsigned char *)ploragw->ppub_msg, MSG_LEN_MAX);
    if (data_len >= MSG_LEN_MAX) {
        data_len = MSG_LEN_MAX - 1;
    }
    if (data_len > 0) {
        memset(&topic_msg, 0x0, sizeof(iotx_mqtt_topic_info_t));
        topic_msg.qos = IOTX_MQTT_QOS1;
        topic_msg.retain = 0;
        topic_msg.dup = 0;
        topic_msg.payload = ploragw->ppub_msg;
        topic_msg.payload_len = data_len;

        snprintf(topicName, sizeof(topicName), "%s/%s/%s", TOPIC_GWCONFIG_UPLOAD, ploragw->auth_info.product_key, ploragw->auth_info.device_name);
        ret = IOT_MQTT_Publish(ploragw->pclient, topicName, &topic_msg);
        if (ret < 0) {
            log_err("IOT_MQTT_Publish failed ret = %d", ret);
        }

        log_info("publish mqtt msg: %s, len: %d\n", ploragw->ppub_msg, data_len);
    }

    return ret;
}

int publish_deviceinfo_upload()
{
    int ret = -1;
    iotx_mqtt_topic_info_t topic_msg;
    aliot_gw_device_info_t devinfo;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    char topicName[TOPIC_NAME_LEN_MAX] = {0};
    char *ota_ver = NULL;

    // call gateway get deviceinfo api
    memset(&devinfo, 0x0, sizeof(devinfo));
    ret = aliot_gw_get_device_info(&devinfo);
    if (0 != ret) {
        log_err("call gatewway get deviceinfo api error, ret: %d\n", ret);
        return -1;
    }

    memset(ploragw->ppub_msg, 0x0, MSG_LEN_MAX);
    ota_ver = config_get_ota_version();
    if (NULL == ota_ver) {
        log_err("get OTA version failed\n");
        sprintf(ploragw->ppub_msg, uploadDeviceinfo, devinfo.gateway_eui, devinfo.model,
                devinfo.manufacturer, devinfo.hw_version, devinfo.sw_version, "");
    } else {
        sprintf(ploragw->ppub_msg, uploadDeviceinfo, devinfo.gateway_eui, devinfo.model,
                devinfo.manufacturer, devinfo.hw_version, devinfo.sw_version, ota_ver);
    }

    memset(&topic_msg, 0x0, sizeof(iotx_mqtt_topic_info_t));
    topic_msg.qos = IOTX_MQTT_QOS1;
    topic_msg.retain = 0;
    topic_msg.dup = 0;
    topic_msg.payload = ploragw->ppub_msg;
    topic_msg.payload_len = strlen(ploragw->ppub_msg);

    snprintf(topicName, sizeof(topicName), "%s/%s/%s", TOPIC_DEVICEINFO_UPLOAD, ploragw->auth_info.product_key, ploragw->auth_info.device_name);
    ret = IOT_MQTT_Publish(ploragw->pclient, topicName, &topic_msg);
    if (ret < 0) {
        log_err("IOT_MQTT_Publish failed ret = %d", ret);
    }

    log_info("publish mqtt msg: %s\n", ploragw->ppub_msg);
    return ret;
}

/**
 * @brief This is a callback function for TOPIC_GWMP_DOWNLINK topic proc
 *
 * @return none
 * @see none.
 * @note none.
 */
static void callback_gwmp_msg_downlink(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    uint32_t msg_len;
    iotx_mqtt_topic_info_pt ptopic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    int ret = 0;

    if (ptopic_info->payload_len < MSG_LEN_MAX - 1) {
        msg_len = ptopic_info->payload_len;
    } else {
        log_info("message is too long, truncate it");
        msg_len = MSG_LEN_MAX - 1;
    }

    // copy the message to mqtt msg buffer
    memset(ploragw->prev_msg, 0x0, MSG_LEN_MAX);
    memcpy(ploragw->prev_msg, ptopic_info->payload, msg_len);

    if (msg_len > GWMP_HEAD_DOWN_LEN) {
        log_info("received mqtt gwmp msg: %s, len: %d\n", ploragw->prev_msg + GWMP_HEAD_DOWN_LEN, msg_len);
    } else {
        log_info("received mqtt gwmp msg len: %d\n", msg_len);
    }
#ifdef ENABLE_ADVANCED_OTA
    HAL_MutexLock(ploragw->check_mutex);
    if(ploragw->checkCnt > 0) {
        //uplink is good && downlink is good too 
        static int ping_cycles = 0;
        ping_cycles ++;
        if(ping_cycles > 5) {
            if( mqtt_notify_update_checkout_result(0, "mqtt connect to the server") < 0) {
                log_err("failed to report mqtt running state to update-deamon!!");
            }
        }
    }
    ploragw->checkCnt = 0;
    HAL_MutexUnlock(ploragw->check_mutex);
#else
    HAL_MutexLock(ploragw->check_mutex);
    ploragw->checkCnt = 0;
    HAL_MutexUnlock(ploragw->check_mutex);
#endif 

    #if defined(ENABLE_ABP_NODES)
    ret = abp_file_conf(ploragw->prev_msg, msg_len);
    if (ret == 1) {
        HAL_MutexLock(ploragw->abp_mutex);
        ploragw->abpdl_flag = 1;
        HAL_MutexUnlock(ploragw->abp_mutex);

        log_info("received abp file config msg, set abpdl_flag: %d", ploragw->abpdl_flag);
        return;
    }
    #endif

#if defined(ENABLE_MONITOR)
    if (msg_len > GWMP_HEAD_DOWN_LEN && ploragw->prev_msg[3] == CUSTOM_MON_MSG_DOWN_ID) {
        ret = mqtt_notify_monitor_gwmp_downlink_msg(ploragw->prev_msg + GWMP_HEAD_DOWN_LEN);
    } else {
#endif        
    // send GWMP message to gateway
    ret = send(ploragw->sock_down, ploragw->prev_msg, msg_len, 0);
    if (ret <= 0) {
        log_err("send gwmp msg error: %d\n", errno);
    } else {
        log_info("send gwmp msg\n");
    }
#if defined(ENABLE_MONITOR)        
    }
#endif

    return;
}

/**
 * @brief This is a callback function for TOPIC_GWCONFIG_DOWNLOAD topic proc
 *
 * @return none
 * @see none.
 * @note none.
 */
static void callback_gwconfig_download(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    uint32_t msg_len;
    iotx_mqtt_topic_info_pt ptopic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    int ret = 0;

    if (ptopic_info->payload_len < MSG_LEN_MAX - 1) {
        msg_len = ptopic_info->payload_len;
    } else {
        log_info("message is too long, truncate it");
        msg_len = MSG_LEN_MAX - 1;
    }

    // copy the message to mqtt msg buffer
    memset(ploragw->prev_msg, 0x0, MSG_LEN_MAX);
    memcpy(ploragw->prev_msg, ptopic_info->payload, msg_len);

    log_info("received mqtt msg: %s, len: %d\n", ploragw->prev_msg, msg_len);

    // call gateway update  global api
    ret = aliot_gw_update_global_conf((unsigned char *)ploragw->prev_msg, msg_len);
    if (0 != ret) {
        log_err("call gatewway update global config api error, ret: %d\n", ret);
    }

    return;
}

/**
 * @brief This is a callback function for TOPIC_GWCONFIG_GET topic proc
 *
 * @return none
 * @see none.
 * @note none.
 */
static void callback_gwconfig_get(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    uint32_t msg_len;
    iotx_mqtt_topic_info_pt ptopic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;

    if (ptopic_info->payload_len < MSG_LEN_MAX - 1) {
        msg_len = ptopic_info->payload_len;
    } else {
        log_info("message is too long, truncate it");
        msg_len = MSG_LEN_MAX - 1;
    }

    // copy the message to mqtt msg buffer
    memset(ploragw->prev_msg, 0x0, MSG_LEN_MAX);
    memcpy(ploragw->prev_msg, ptopic_info->payload, msg_len);

    log_info("received mqtt msg: %s\n", ploragw->prev_msg);

    // publish gw config to server
    publish_gwconfig_upload();

    return;
}

/**
 * @brief This is a callback function for TOPIC_DEVICEINFO_GET topic proc
 *
 * @return none
 * @see none.
 * @note none.
 */
static void callback_deviceinfo_get(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    uint32_t msg_len;
    iotx_mqtt_topic_info_pt ptopic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;

    if (ptopic_info->payload_len < MSG_LEN_MAX - 1) {
        msg_len = ptopic_info->payload_len;
    } else {
        log_info("message is too long, truncate it");
        msg_len = MSG_LEN_MAX - 1;
    }

    // copy the message to mqtt msg buffer
    memset(ploragw->prev_msg, 0x0, MSG_LEN_MAX);
    memcpy(ploragw->prev_msg, ptopic_info->payload, msg_len);

    log_info("received mqtt msg: %s\n", ploragw->prev_msg);

    // publish deviceinfo to server
    publish_deviceinfo_upload();

    return;
}

/**
 * @brief This is a callback function for TOPIC_GW_RESET topic proc
 *
 * @return none
 * @see none.
 * @note none.
 */
static void callback_gw_reset(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    uint32_t msg_len;
    iotx_mqtt_topic_info_pt ptopic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    int ret = 0;

    if (ptopic_info->payload_len < MSG_LEN_MAX - 1) {
        msg_len = ptopic_info->payload_len;
    } else {
        log_info("message is too long, truncate it");
        msg_len = MSG_LEN_MAX - 1;
    }

    // copy the message to mqtt msg buffer
    memset(ploragw->prev_msg, 0x0, MSG_LEN_MAX);
    memcpy(ploragw->prev_msg, ptopic_info->payload, msg_len);

    log_info("received mqtt msg: %s\n", ploragw->prev_msg);
#if defined(ENABLE_MONITOR)
    mqtt_send_monitor_alarm(MON_ALARM_REBOOT, "callback_gw_reset");
#endif    
    // call gateway reset api
    ret = aliot_gw_reset();
    if (0 != ret) {
        log_err("call gateway reset api error, ret: %d\n", ret);
    }

    return;
}

#if defined(ENABLE_REMOTE_CTRL_SSH)
static int open_remote_debug(const char *path)
{
    struct stat st;
    int ret = 0;
    char buf[512] = {0};
    if(!path)
        return -1;

    ret = stat(path, &st);

    if(ret == -1){
        log_err("Failed to stat %s\n", path);
        return -1;
    }

    if(!S_ISREG(st.st_mode)){
        log_err("%s is not a file\n", path);
        return -2;
    }

    snprintf(buf, sizeof(buf), "%s &>/dev/null &", path);
    ret = system(buf);

    return ret;
}

int close_remote_debug()
{
    int ret = 0;
    char buf[256] = {0};

    system("systemctl stop sshd.socket");

    sleep(1);
    snprintf(buf, sizeof(buf), "kill -2 `cat /tmp/sshd_agent.pid`");

    sleep(1);
    ret = system(buf);

    return ret;
}


static void callback_remote_ctrl_ssh(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    char buff[FILENAME_MAX+1] = {0};
    char abs_path[FILENAME_MAX] = {0};
    uint32_t msg_len;
    iotx_mqtt_topic_info_pt ptopic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    int read_len = 0;
    char *tmp = NULL;
    int ret = 0;

    if (ptopic_info->payload_len < MSG_LEN_MAX - 1) {
        msg_len = ptopic_info->payload_len;
    } else {
        log_info("message is too long, truncate it");
        msg_len = MSG_LEN_MAX - 1;
    }

    // copy the message to mqtt msg buffer
    memset(ploragw->prev_msg, 0x0, MSG_LEN_MAX);
    memcpy(ploragw->prev_msg, ptopic_info->payload, msg_len);

    log_info("received mqtt msg: %s\n", ploragw->prev_msg);
    //switch ssh
    if (0 == strcmp(ploragw->prev_msg, "on")) {
        ret = aliot_platform_ssh_enable(1);
    } else if (0 == strcmp(ploragw->prev_msg, "off")) {
        ret = aliot_platform_ssh_enable(0);
    }
    if (0 != ret) {
        log_err("call ssh enable api error, ret: %d\n", ret);
        return;
    }

    //get sshd_agent path
    memset(buff, 0, FILENAME_MAX+1);
    read_len = readlink("/proc/self/exe", buff, FILENAME_MAX);
    if(read_len <= 0){
        log_err("sshd_agent(remote debug) bin file not exsist.\n");
        return;
    }
    buff[read_len] = 0;
    tmp = strrchr(buff, '/');
    if(tmp){
        buff[tmp - buff]='\0';
    }

    snprintf(abs_path, FILENAME_MAX, "%s/%s", buff, "sshd_agent");
    //swicth remote debug
    if (0 == strcmp(ploragw->prev_msg, "on")) {
        log_info("opening remote debug...\n");
        ret = open_remote_debug(abs_path);
        if(ret == 0){
            log_info("open remote debug process success.\n");
        }else{
            log_err("Failed to open remote debug process: %d:%s.\n", ret, strerror(errno));
        }
    } else if (0 == strcmp(ploragw->prev_msg, "off")) {
        log_info("closing remote debug...\n");
        ret = close_remote_debug();
        if(ret == 0){
            log_info("close remote debug process success.\n");
        }else{
            log_err("Failed to close remote debug process: %d.\n", ret);
        }
    }
    if (0 != ret) {
        log_err("call remote debug enable api error, ret: %d\n", ret);
    }

    return;
}
#endif

#if defined(ENABLE_REMOTE_CTRL_UART)
static void callback_remote_ctrl_uart(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    uint32_t msg_len;
    iotx_mqtt_topic_info_pt ptopic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    int ret = 0;

    if (ptopic_info->payload_len < MSG_LEN_MAX - 1) {
        msg_len = ptopic_info->payload_len;
    } else {
        log_info("message is too long, truncate it");
        msg_len = MSG_LEN_MAX - 1;
    }

    // copy the message to mqtt msg buffer
    memset(ploragw->prev_msg, 0x0, MSG_LEN_MAX);
    memcpy(ploragw->prev_msg, ptopic_info->payload, msg_len);

    log_info("received mqtt msg: %s\n", ploragw->prev_msg);
    if (0 == strcmp(ploragw->prev_msg, "on")) {
        ret = aliot_platform_uart_enable(1);
    } else if (0 == strcmp(ploragw->prev_msg, "off")) {
        ret = aliot_platform_uart_enable(0);
    }
    if (0 != ret) {
        log_err("call uart enable api error, ret: %d\n", ret);
    }

    return;
}
#endif

/**
 * @brief This is a callback function for TOPIC_LOG_UPLOAD topic proc
 *
 * @return none
 * @see none.
 * @note none.
 */
#if defined(ENABLE_REMOTE_LOG)
static void callback_filelog_upload(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    uint32_t msg_len;
    iotx_mqtt_topic_info_pt ptopic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;

    if (ptopic_info->payload_len < MSG_LEN_MAX - 1) {
        msg_len = ptopic_info->payload_len;
    } else {
        log_info("message is too long, truncate it");
        msg_len = MSG_LEN_MAX - 1;
    }

    // copy the message to mqtt msg buffer
    memset(ploragw->prev_msg, 0x0, MSG_LEN_MAX);
    memcpy(ploragw->prev_msg, ptopic_info->payload, msg_len);

    log_info("received mqtt msg: %s, upload filelog\n", ploragw->prev_msg);

    // set upload filelog flag
    HAL_MutexLock(ploragw->log_mutex);
    ploragw->uploadlog_flag = 1;
    HAL_MutexUnlock(ploragw->log_mutex);

    log_info("set uploadlog flag: %d\n", ploragw->uploadlog_flag);
    return;
}
#endif

void thread_gwmp_msg_uplink(void)
{
    struct sockaddr_storage dist_addr;
    socklen_t addr_len = sizeof(dist_addr);
    char *pdatabuf = NULL;
    int byte_nb = 0;
    fd_set sets;
    int flags;
    int ret = -1;
	int rc = 0;
    struct timeval timeout;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    #if defined(ENABLE_WATCHDOG)
    struct timespec watchdog_time_keeper;
    clock_gettime(CLOCK_MONOTONIC, &watchdog_time_keeper);
    #endif
	
    pdatabuf = (char *)HAL_Malloc(MSG_LEN_MAX);
    if (NULL == pdatabuf) {
        log_err("malloc data buf error");
        return;
    }

    if ((flags = fcntl(ploragw->sock_up, F_GETFL, 0)) < 0) {
        log_err("fcntl F_GETFL error: %d\n", errno);
        HAL_Free(pdatabuf);
        return;
    }
    if (fcntl(ploragw->sock_up, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_err("fcntl F_SETFL error: %d\n", errno);
        HAL_Free(pdatabuf);
        return;
    }

    /* wait to receive a gateway UDP request packet */
    log_info("waiting to receive a gw UDP request\n");

    while (!native_exit_sig) {
        FD_ZERO(&sets);
        FD_SET(ploragw->sock_up, &sets);

        timeout.tv_sec = 3;
        timeout.tv_usec = 0;

        ret = select(ploragw->sock_up + 1, &sets, NULL, NULL, &timeout);
        if (ret > 0) {
            if (FD_ISSET(ploragw->sock_up, &sets)) {
                memset(pdatabuf, 0x0, MSG_LEN_MAX);
                byte_nb = recvfrom(ploragw->sock_up, pdatabuf, MSG_LEN_MAX - 1, 0, (struct sockaddr *)&dist_addr, &addr_len);
                if (byte_nb > 0) {
                    pdatabuf[byte_nb] = 0;
                    log_info("received gwmp msg len: %d\n", byte_nb);

                    // publish GWMP message to server
                    publish_gwmp_msg_uplink(pdatabuf, byte_nb);          

                    #if defined(ENABLE_ABP_NODES)
                    // send to native lora server
                    if (abp_out_enable != 0) {
                        rc = send(ploragw->native_sock_up, pdatabuf, byte_nb, 0);
                        if (rc <= 0) {
                            log_info("send native up gwmp msg: %d\n", errno);
                        } else {
                            log_info("send native up gwmp msg\n");
                        }
                    }
                    #endif
                } else if (byte_nb == 0) {
                    log_err("connection is closed");
                    HAL_SleepMs(100);
                } else {
                    if (errno != EAGAIN)  {
                        log_err("recvfrom gwmp msg error: %d\n", errno);
                    }
                    HAL_SleepMs(100);
                }
            }
        } else if (0 == ret) {
            // select timeout
        } else {
            log_err("select-recv gwmp socket error: %d\n", errno);
            HAL_SleepMs(100);
        }

        #if defined(ENABLE_WATCHDOG)			
        if(thread_feeddog_periodically(MQTT_SYMBOL, THRD_ID_UPLINK, 30, 60, &watchdog_time_keeper) < 0) {
            log_err("uplink thread feeddog failed\n");
        }
        #endif  
    }

    HAL_Free(pdatabuf);

    #if defined(ENABLE_WATCHDOG)	
    thread_cancel_feeddog(MQTT_SYMBOL, THRD_ID_UPLINK);
    #endif

    return;
}

#if defined(ENABLE_MONITOR)
int loragw_ipc_monitor_msg_uplink_send(const char * msg_body);

static int mon_util_strtol(char *str, uint32_t *in_val)
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

#define PROTOCOL_VERSION    2           /* v1.3 */
#define GWMP_HEAD_UP_LEN    12

static char g_mqtt_dbus_msg[MSG_LEN_MAX];

static int mqtt_fill_monitor_gwmp_header(char *msg)
{
    char eui_h[9] = {'\0'};
    char eui_l[9] = {'\0'};
    uint32_t eui_h_val = 0;
    uint32_t eui_l_val = 0;
    aliot_gw_device_info_t devinfo;

    /* fill header */
    msg[0] = PROTOCOL_VERSION;
    msg[1] = (uint8_t)rand();
    msg[2] = (uint8_t)rand();
    msg[3] = CUSTOM_MON_MSG_UP_ID;
    aliot_gw_get_device_info(&devinfo);
    strncpy(eui_h, devinfo.gateway_eui, 8);
    strncpy(eui_l, devinfo.gateway_eui + 8, 8);
    mon_util_strtol(eui_h, &eui_h_val);
    mon_util_strtol(eui_l, &eui_l_val);

    *(uint32_t *)(msg + 4) = eui_h_val;
    *(uint32_t *)(msg + 8) = eui_l_val;

    return 0;
}

int loragw_ipc_monitor_msg_uplink_send(const char * msg_body)
{
    if(!msg_body || strlen(msg_body)==0 )
        return -1;

    int byte_nb = strlen(msg_body);

    log_debug("received dbus msg len: %d\n", byte_nb);

    if (byte_nb > MSG_LEN_MAX - GWMP_HEAD_UP_LEN) {
        log_err("dbus msg = %d too long\n");
        
        return -1;
    }

    memset(g_mqtt_dbus_msg, '\0', MSG_LEN_MAX);
    strncpy(g_mqtt_dbus_msg + GWMP_HEAD_UP_LEN, msg_body, byte_nb);
    mqtt_fill_monitor_gwmp_header(g_mqtt_dbus_msg);

    // publish GWMP full message to server
    return publish_gwmp_msg_uplink(g_mqtt_dbus_msg, byte_nb + GWMP_HEAD_UP_LEN);
}
#endif

int create_gw_upd_msg(void)
{
    int i;
    pthread_t thrid_up;
    uint16_t upd_port_up;
    uint16_t upd_port_down;
    char udp_port[16] = {0};
    iotx_lorogw_t *ploragw = &g_iotx_loragw;

    struct addrinfo hints;
    /* store result of getaddrinfo */
    struct addrinfo *result;
    /* pointer to move into *result data */
    struct addrinfo *q;

    /* prepare hints to open network sockets */
    memset(&hints, 0, sizeof hints);
    /* should handle IP v4 or v6 automatically */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    // call gateway get upd port up
    upd_port_up = aliot_gw_get_udp_port_up();
    log_info("upd_port_up: %u\n", upd_port_up);
    sprintf(udp_port, "%d", upd_port_up);

    /* look for upd local address /upstream port */
    i = getaddrinfo(UDP_LOCALHOST_ADDR, udp_port, &hints, &result);
    if (i != 0) {
        log_err("upstream getaddrinfo returned, error: %s\n", gai_strerror(i));
        return -1;
    }

    /* try to open socket and bind to it */
    for (q = result; q != NULL; q = q->ai_next) {
        ploragw->sock_up = socket(q->ai_family, q->ai_socktype, q->ai_protocol);
        if (ploragw->sock_up == -1) {
            /* socket failed, try next field */
            continue;
        } else {
            i = bind(ploragw->sock_up, q->ai_addr, q->ai_addrlen);
            if (i == -1) {
                log_err("bind up socket, error: %s\n", gai_strerror(i));
                close(ploragw->sock_up);
                ploragw->sock_up = -1;
                /* bind failed, try next field */
                continue;
            } else {
                /* success, get out of loop */
                break;
            }
        }
    }
    if (q == NULL) {
        log_err("failed to open socket or to bind to it\n");
        freeaddrinfo(result);
        return -1;
    }
    freeaddrinfo(result);

    // call gateway get upd port down
    upd_port_down = aliot_gw_get_udp_port_down();
    log_info("upd_port_down: %u\n", upd_port_down);
    sprintf(udp_port, "%d", upd_port_down);

    /* look for upd local address /downstream port */
    i = getaddrinfo(UDP_LOCALHOST_ADDR, udp_port, &hints, &result);
    if (i != 0) {
        log_err("downstream getaddrinfo returned, error: %s\n", gai_strerror(i));
        close(ploragw->sock_up);
        ploragw->sock_up = -1;
        return -1;
    }

    /* try to open socket and connect to it */
    for (q = result; q != NULL; q = q->ai_next) {
        ploragw->sock_down = socket(q->ai_family, q->ai_socktype, q->ai_protocol);
        if (ploragw->sock_down == -1) {
            /* socket failed, try next field */
            continue;
        } else {
            i = connect(ploragw->sock_down, q->ai_addr, q->ai_addrlen);
            if (i == -1) {
                log_err("connect down socket, error: %s\n", gai_strerror(i));
                close(ploragw->sock_down);
                ploragw->sock_down = -1;
                /* connect failed, try next field */
                continue;
            } else {
                /* success, get out of loop */
                break;
            }
        }
    }
    if (q == NULL) {
        log_err("failed to open socket or to connect to it\n");
        close(ploragw->sock_up);
        ploragw->sock_up = -1;
        freeaddrinfo(result);
        return -1;
    }
    freeaddrinfo(result);

    i = pthread_create(&thrid_up, NULL, (void * ( *)(void *))thread_gwmp_msg_uplink, NULL);
    if (i != 0) {
        log_err("impossible to create uplink thread\n");
        close(ploragw->sock_down);
        close(ploragw->sock_up);
        ploragw->sock_up = -1;
        ploragw->sock_down = -1;
        return -1;
    }

    return 0;
}

#if defined(ENABLE_ABP_NODES)
void thread_native_msg_downlink(void)
{
    struct sockaddr_storage dist_addr;
    socklen_t addr_len = sizeof(dist_addr);
    char *pdatabuf = NULL;
    int byte_nb = 0;
    fd_set sets;
    int flags;
    int ret = -1;
    int rc = 0;
    struct timeval timeout;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    #if defined(ENABLE_WATCHDOG)
    struct timespec watchdog_time_keeper;
    clock_gettime(CLOCK_MONOTONIC, &watchdog_time_keeper);
    #endif
	
    pdatabuf = (char *)HAL_Malloc(MSG_LEN_MAX);
    if (NULL == pdatabuf) {
        log_err("malloc data buf error");
        return;
    }

    if ((flags = fcntl(ploragw->native_sock_down, F_GETFL, 0)) < 0) {
        log_err("fcntl F_GETFL error: %d\n", errno);
        HAL_Free(pdatabuf);
        return;
    }
    if (fcntl(ploragw->native_sock_down, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_err("fcntl F_SETFL error: %d\n", errno);
        HAL_Free(pdatabuf);
        return;
    }

    /* wait to receive native UDP down packet */
    log_info("waiting to receive native UDP down packet\n");

    while (!native_exit_sig) {
        FD_ZERO(&sets);
        FD_SET(ploragw->native_sock_down, &sets);

        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        ret = select(ploragw->native_sock_down + 1, &sets, NULL, NULL, &timeout);
        if (ret > 0) {
            if (FD_ISSET(ploragw->native_sock_down, &sets)) {
                memset(pdatabuf, 0x0, MSG_LEN_MAX);
                byte_nb = recvfrom(ploragw->native_sock_down, pdatabuf, MSG_LEN_MAX - 1, 0, (struct sockaddr *)&dist_addr, &addr_len);
                if (byte_nb > 0) {
                    pdatabuf[byte_nb] = 0;

                    if (byte_nb > GWMP_HEAD_DOWN_LEN) {
                        log_info("received native down gwmp msg: %s, len: %d\n", pdatabuf + GWMP_HEAD_DOWN_LEN, byte_nb);
                    } else {
                        log_info("received native down gwmp msg len: %d\n", byte_nb);
                    }
					
					lora_ns_server_exist = 1;
                    // send native GWMP message to gateway
                    rc = send(ploragw->sock_down, pdatabuf, byte_nb, 0);
                    if (rc <= 0) {
                        log_err("send native down gwmp msg error: %d\n", errno);
                    } else {
                        log_info("send native down gwmp msg\n");
                    }
                } else if (byte_nb == 0) {
                    log_err("connection is closed");
                    HAL_SleepMs(100);
                } else {
                    if (errno != EAGAIN)  {
                        log_err("recvfrom native gwmp msg error: %d\n", errno);
                    }
                    HAL_SleepMs(100);
                }
            }
        } else if (0 == ret) {
            // select timeout
        } else {
            log_err("select-recv native down gwmp socket error: %d\n", errno);
            HAL_SleepMs(100);
        }

        #if defined(ENABLE_WATCHDOG)			
        if(thread_feeddog_periodically(MQTT_SYMBOL, THRD_ID_NAT_DOWNLINK, 30, 60, &watchdog_time_keeper) < 0) {
            log_err("native downlink thread feeddog failed\n");
        }
        #endif
    }

    HAL_Free(pdatabuf);

    #if defined(ENABLE_WATCHDOG)
    thread_cancel_feeddog(MQTT_SYMBOL, THRD_ID_NAT_DOWNLINK);
    #endif

    return;
}

int create_native_upd_msg(void)
{
    int i;
    pthread_t thrid_down;
    uint16_t upd_port_up = 28888;
    uint16_t upd_port_down = 29999;
    char udp_port[16] = {0};
    iotx_lorogw_t *ploragw = &g_iotx_loragw;

    struct addrinfo hints;
    /* store result of getaddrinfo */
    struct addrinfo *result;
    /* pointer to move into *result data */
    struct addrinfo *q;

    /* prepare hints to open network sockets */
    memset(&hints, 0, sizeof hints);
    /* should handle IP v4 or v6 automatically */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    /* look for upd local address /upstream port */
    sprintf(udp_port, "%d", upd_port_up);
    i = getaddrinfo(UDP_LOCALHOST_ADDR, udp_port, &hints, &result);
    if (i != 0) {
        log_err("upstream getaddrinfo returned, error: %s\n", gai_strerror(i));
        return -1;
    }

    /* try to open socket and bind to it */
    for (q = result; q != NULL; q = q->ai_next) {
        ploragw->native_sock_up = socket(q->ai_family, q->ai_socktype, q->ai_protocol);
        if (ploragw->native_sock_up == -1) {
            /* socket failed, try next field */
            continue;
        } else {
            i = connect(ploragw->native_sock_up, q->ai_addr, q->ai_addrlen);
            if (i == -1) {
                log_err("connect up socket, error: %s\n", gai_strerror(i));
                close(ploragw->native_sock_up);
                ploragw->native_sock_up = -1;
                /* connect failed, try next field */
                continue;
            } else {
                /* success, get out of loop */
                break;
            }
        }
    }
    if (q == NULL) {
        log_err("failed to open socket or to connect to it\n");
        freeaddrinfo(result);
        return -1;
    }
    freeaddrinfo(result);

    /* look for upd local address /downstream port */
    sprintf(udp_port, "%d", upd_port_down);
    i = getaddrinfo(UDP_LOCALHOST_ADDR, udp_port, &hints, &result);
    if (i != 0) {
        log_err("downstream getaddrinfo returned, error: %s\n", gai_strerror(i));
        close(ploragw->native_sock_up);
        ploragw->native_sock_up = -1;
        return -1;
    }

    /* try to open socket and connect to it */
    for (q = result; q != NULL; q = q->ai_next) {
        ploragw->native_sock_down = socket(q->ai_family, q->ai_socktype, q->ai_protocol);
        if (ploragw->native_sock_down == -1) {
            /* socket failed, try next field */
            continue;
        } else {
            i = bind(ploragw->native_sock_down, q->ai_addr, q->ai_addrlen);
            if (i == -1) {
                log_err("bind down socket, error: %s\n", gai_strerror(i));
                close(ploragw->native_sock_down);
                ploragw->native_sock_down = -1;
                /* bind failed, try next field */
                continue;
            } else {
                /* success, get out of loop */
                break;
            }
        }
    }
    if (q == NULL) {
        log_err("failed to open socket or to bind to it\n");
        close(ploragw->native_sock_up);
        ploragw->native_sock_up = -1;
        freeaddrinfo(result);
        return -1;
    }
    freeaddrinfo(result);

    i = pthread_create(&thrid_down, NULL, (void * ( *)(void *))thread_native_msg_downlink, NULL);
    if (i != 0) {
        log_err("impossible to create native down thread\n");
        close(ploragw->native_sock_down);
        close(ploragw->native_sock_up);
        ploragw->native_sock_up = -1;
        ploragw->native_sock_down = -1;
        return -1;
    }

    return 0;
}
#endif

void unsubscribe_topics(void)
{
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    
    if (NULL != ploragw->ptpc_gwmp_dl) {
        IOT_MQTT_Unsubscribe(ploragw->pclient, ploragw->ptpc_gwmp_dl);
        HAL_Free(ploragw->ptpc_gwmp_dl);
    }

    if (NULL != ploragw->ptpc_custom_dl) {
        IOT_MQTT_Unsubscribe(ploragw->pclient, ploragw->ptpc_custom_dl);
        HAL_Free(ploragw->ptpc_custom_dl);
    }

    if (NULL != ploragw->ptpc_gwconf_dl) {
        IOT_MQTT_Unsubscribe(ploragw->pclient, ploragw->ptpc_gwconf_dl);
        HAL_Free(ploragw->ptpc_gwconf_dl);
    }

    if (NULL != ploragw->ptpc_gwconf_get) {
        IOT_MQTT_Unsubscribe(ploragw->pclient, ploragw->ptpc_gwconf_get);
        HAL_Free(ploragw->ptpc_gwconf_get);
    }

    if (NULL != ploragw->ptpc_devinfo_get) {
        IOT_MQTT_Unsubscribe(ploragw->pclient, ploragw->ptpc_devinfo_get);
        HAL_Free(ploragw->ptpc_devinfo_get);
    }

    if (NULL != ploragw->ptpc_gw_reset) {
        IOT_MQTT_Unsubscribe(ploragw->pclient, ploragw->ptpc_gw_reset);
        HAL_Free(ploragw->ptpc_gw_reset);
    }

    if (NULL != ploragw->ptpc_log_upload) {
        IOT_MQTT_Unsubscribe(ploragw->pclient, ploragw->ptpc_log_upload);
        HAL_Free(ploragw->ptpc_log_upload);
    }

    if (NULL != ploragw->ptpc_log_upload_user) {
        IOT_MQTT_Unsubscribe(ploragw->pclient, ploragw->ptpc_log_upload_user);
        HAL_Free(ploragw->ptpc_log_upload_user);
    }

    if (NULL != ploragw->ptpc_ctrl_ssh) {
        IOT_MQTT_Unsubscribe(ploragw->pclient, ploragw->ptpc_ctrl_ssh);
        HAL_Free(ploragw->ptpc_ctrl_ssh);
    }

    if (NULL != ploragw->ptpc_ctrl_ssh_user) {
        IOT_MQTT_Unsubscribe(ploragw->pclient, ploragw->ptpc_ctrl_ssh_user);
        HAL_Free(ploragw->ptpc_ctrl_ssh_user);
    }

    if (NULL != ploragw->ptpc_ctrl_uart) {
        IOT_MQTT_Unsubscribe(ploragw->pclient, ploragw->ptpc_ctrl_uart);
        HAL_Free(ploragw->ptpc_ctrl_uart);
    }

    if (NULL != ploragw->ptpc_ctrl_uart_user) {
        IOT_MQTT_Unsubscribe(ploragw->pclient, ploragw->ptpc_ctrl_uart_user);
        HAL_Free(ploragw->ptpc_ctrl_uart_user);
    }

    return;
}

int subscribe_topics(void)
{
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    int ret = -1, ret1 = -1;
    
    ploragw->ptpc_gwmp_dl = (char *)HAL_Malloc(TOPIC_NAME_LEN_MAX);
    if (NULL != ploragw->ptpc_gwmp_dl) {
        snprintf(ploragw->ptpc_gwmp_dl, TOPIC_NAME_LEN_MAX, "%s/%s/%s", TOPIC_GWMP_DOWNLINK, ploragw->auth_info.product_key, ploragw->auth_info.device_name);
        ret = IOT_MQTT_Subscribe(ploragw->pclient, ploragw->ptpc_gwmp_dl, IOTX_MQTT_QOS1, callback_gwmp_msg_downlink, NULL);
        if (ret < 0) {
            log_err("subscribe topic:%s error\n", TOPIC_GWMP_DOWNLINK);
            return ret;
        }
    }

    ploragw->ptpc_custom_dl = (char *)HAL_Malloc(TOPIC_NAME_LEN_MAX);
    if (NULL != ploragw->ptpc_custom_dl) {
        snprintf(ploragw->ptpc_custom_dl, TOPIC_NAME_LEN_MAX, "/sys/%s/%s%s", ploragw->auth_info.product_key, ploragw->auth_info.device_name, TOPIC_CUSTOM_DOWNLINK);
        ret = IOT_MQTT_Subscribe(ploragw->pclient, ploragw->ptpc_custom_dl, IOTX_MQTT_QOS1, callback_gwmp_msg_downlink, NULL);
        if (ret < 0) {
            log_err("subscribe topic:%s error\n", TOPIC_CUSTOM_DOWNLINK);
            return ret;
        }
    }

    ploragw->ptpc_gwconf_dl = (char *)HAL_Malloc(TOPIC_NAME_LEN_MAX);
    if (NULL != ploragw->ptpc_gwconf_dl) {
        snprintf(ploragw->ptpc_gwconf_dl, TOPIC_NAME_LEN_MAX, "%s/%s/%s", TOPIC_GWCONFIG_DOWNLOAD, ploragw->auth_info.product_key, ploragw->auth_info.device_name);
        ret = IOT_MQTT_Subscribe(ploragw->pclient, ploragw->ptpc_gwconf_dl, IOTX_MQTT_QOS1, callback_gwconfig_download, NULL);
        if (ret < 0) {
            log_err("subscribe topic:%s error\n", TOPIC_GWCONFIG_DOWNLOAD);
            return ret;
        }
    }

    ploragw->ptpc_gwconf_get = (char *)HAL_Malloc(TOPIC_NAME_LEN_MAX);
    if (NULL != ploragw->ptpc_gwconf_get) {
        snprintf(ploragw->ptpc_gwconf_get, TOPIC_NAME_LEN_MAX, "%s/%s/%s", TOPIC_GWCONFIG_GET, ploragw->auth_info.product_key, ploragw->auth_info.device_name);
        ret = IOT_MQTT_Subscribe(ploragw->pclient, ploragw->ptpc_gwconf_get, IOTX_MQTT_QOS1, callback_gwconfig_get, NULL);
        if (ret < 0) {
            log_err("subscribe topic:%s error\n", TOPIC_GWCONFIG_GET);
            return ret;
        }
    }

    ploragw->ptpc_devinfo_get = (char *)HAL_Malloc(TOPIC_NAME_LEN_MAX);
    if (NULL != ploragw->ptpc_devinfo_get) {
        snprintf(ploragw->ptpc_devinfo_get, TOPIC_NAME_LEN_MAX, "%s/%s/%s", TOPIC_DEVICEINFO_GET, ploragw->auth_info.product_key, ploragw->auth_info.device_name);
        ret = IOT_MQTT_Subscribe(ploragw->pclient, ploragw->ptpc_devinfo_get, IOTX_MQTT_QOS1, callback_deviceinfo_get, NULL);
        if (ret < 0) {
            log_err("subscribe topic:%s error\n", TOPIC_DEVICEINFO_GET);
            return ret;
        }
    }

    ploragw->ptpc_gw_reset = HAL_Malloc(TOPIC_NAME_LEN_MAX);
    if (NULL != ploragw->ptpc_gw_reset) {
        snprintf(ploragw->ptpc_gw_reset, TOPIC_NAME_LEN_MAX, "%s/%s/%s", TOPIC_GW_RESET, ploragw->auth_info.product_key, ploragw->auth_info.device_name);
        ret = IOT_MQTT_Subscribe(ploragw->pclient, ploragw->ptpc_gw_reset, IOTX_MQTT_QOS1, callback_gw_reset, NULL);
        if (ret < 0) {
            log_err("subscribe topic:%s error\n", TOPIC_GW_RESET);
            return ret;
        }
    }

    #if defined(ENABLE_REMOTE_LOG)
    ploragw->ptpc_log_upload = (char *)HAL_Malloc(TOPIC_NAME_LEN_MAX);
    if (NULL != ploragw->ptpc_log_upload) {
        snprintf(ploragw->ptpc_log_upload, TOPIC_NAME_LEN_MAX, "/%s/%s%s", ploragw->auth_info.product_key, ploragw->auth_info.device_name, TOPIC_LOG_UPLOAD);
        ret1 = IOT_MQTT_Subscribe(ploragw->pclient, ploragw->ptpc_log_upload, IOTX_MQTT_QOS1, callback_filelog_upload, NULL);
        if (ret1 < 0) {
            log_err("subscribe topic:%s error, no exit\n", TOPIC_LOG_UPLOAD);
        }
    }
    ploragw->ptpc_log_upload_user = (char *)HAL_Malloc(TOPIC_NAME_LEN_MAX);
    if (NULL != ploragw->ptpc_log_upload_user) {
        snprintf(ploragw->ptpc_log_upload_user, TOPIC_NAME_LEN_MAX, "/%s/%s/user%s", ploragw->auth_info.product_key, ploragw->auth_info.device_name, TOPIC_LOG_UPLOAD);
        ret1 = IOT_MQTT_Subscribe(ploragw->pclient, ploragw->ptpc_log_upload_user, IOTX_MQTT_QOS1, callback_filelog_upload, NULL);
        if (ret1 < 0) {
            log_err("subscribe topic:user/%s error, no exit\n", TOPIC_LOG_UPLOAD);
        }
    }
    #endif

    #if defined(ENABLE_REMOTE_CTRL_SSH)
    ploragw->ptpc_ctrl_ssh = (char *)HAL_Malloc(TOPIC_NAME_LEN_MAX);
    if (NULL != ploragw->ptpc_ctrl_ssh) {
        snprintf(ploragw->ptpc_ctrl_ssh, TOPIC_NAME_LEN_MAX, "/%s/%s%s", ploragw->auth_info.product_key, ploragw->auth_info.device_name, TOPIC_CTRL_SSH);
        ret1 = IOT_MQTT_Subscribe(ploragw->pclient, ploragw->ptpc_ctrl_ssh, IOTX_MQTT_QOS1, callback_remote_ctrl_ssh, NULL);
        if (ret1 < 0) {
            log_err("subscribe topic:%s error, no exit\n", TOPIC_CTRL_SSH);
        }
    }
    ploragw->ptpc_ctrl_ssh_user = (char *)HAL_Malloc(TOPIC_NAME_LEN_MAX);
    if (NULL != ploragw->ptpc_ctrl_ssh_user) {
        snprintf(ploragw->ptpc_ctrl_ssh_user, TOPIC_NAME_LEN_MAX, "/%s/%s/user%s", ploragw->auth_info.product_key, ploragw->auth_info.device_name, TOPIC_CTRL_SSH);
        ret1 = IOT_MQTT_Subscribe(ploragw->pclient, ploragw->ptpc_ctrl_ssh_user, IOTX_MQTT_QOS1, callback_remote_ctrl_ssh, NULL);
        if (ret1 < 0) {
            log_err("subscribe topic:user/%s error, no exit\n", TOPIC_CTRL_SSH);
        }
    }
    #endif

    #if defined(ENABLE_REMOTE_CTRL_UART)
    ploragw->ptpc_ctrl_uart = (char *)HAL_Malloc(TOPIC_NAME_LEN_MAX);
    if (NULL != ploragw->ptpc_ctrl_uart) {
        snprintf(ploragw->ptpc_ctrl_uart, TOPIC_NAME_LEN_MAX, "/%s/%s%s", ploragw->auth_info.product_key, ploragw->auth_info.device_name, TOPIC_CTRL_UART);
        ret1 = IOT_MQTT_Subscribe(ploragw->pclient, ploragw->ptpc_ctrl_uart, IOTX_MQTT_QOS1, callback_remote_ctrl_uart, NULL);
        if (ret1 < 0) {
            log_err("subscribe topic:%s error, no exit\n", TOPIC_CTRL_UART);
        }
    }
    ploragw->ptpc_ctrl_uart_user = (char *)HAL_Malloc(TOPIC_NAME_LEN_MAX);
    if (NULL != ploragw->ptpc_ctrl_uart_user) {
        snprintf(ploragw->ptpc_ctrl_uart_user, TOPIC_NAME_LEN_MAX, "/%s/%s/user%s", ploragw->auth_info.product_key, ploragw->auth_info.device_name, TOPIC_CTRL_UART);
        ret1 = IOT_MQTT_Subscribe(ploragw->pclient, ploragw->ptpc_ctrl_uart_user, IOTX_MQTT_QOS1, callback_remote_ctrl_uart, NULL);
        if (ret1 < 0) {
            log_err("subscribe topic:user/%s error, no exit\n", TOPIC_CTRL_UART);
        }
    }
    #endif

    return ret;
}

int mqtt_client(char *msg_buf, char *msg_readbuf)
{
    int rc = 0;
    iotx_conn_info_pt pconn_info;
    iotx_mqtt_param_t mqtt_params;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    #if defined(ENABLE_MSG_CACHE)
    pthread_t thrid_msg_cache;
    #endif
    pthread_t thrid_file;
    #if defined(ENABLE_OTA)
    pthread_t thrid_ota;
    #endif
    #if defined(ENABLE_WATCHDOG)
    struct timespec watchdog_time_keeper;
    clock_gettime(CLOCK_MONOTONIC, &watchdog_time_keeper);
    #endif

    // call gateway get auth info api
    memset(&ploragw->auth_info, 0x0, sizeof(aliot_gw_auth_info_t));
    rc = aliot_gw_get_auth_info(&ploragw->auth_info);
    if (0 != rc) {
        log_err("call gateway get auth info api error!");
        return -1;
    }

    // device auth
    if (0 != IOT_SetupConnInfo(ploragw->auth_info.product_key, 
                               ploragw->auth_info.device_name,
                               ploragw->auth_info.device_secret,
                               (void **)&pconn_info)) {
        log_err("IOT_SetupConnInfo() error!");
        return -1;
    }

    memset(&mqtt_params, 0x0, sizeof(mqtt_params));
    mqtt_params.port = pconn_info->port;
    mqtt_params.host = pconn_info->host_name;
    mqtt_params.client_id = pconn_info->client_id;
    mqtt_params.username = pconn_info->username;
    mqtt_params.password = pconn_info->password;
    mqtt_params.pub_key = pconn_info->pub_key;
    mqtt_params.request_timeout_ms = 2000;
    mqtt_params.clean_session = 0;
    mqtt_params.keepalive_interval_ms = 60000;
    // mqtt_params.pread_buf = msg_readbuf;
    mqtt_params.read_buf_size = MSG_LEN_MAX;
    // mqtt_params.pwrite_buf = msg_buf;
    mqtt_params.write_buf_size = MSG_LEN_MAX;
    mqtt_params.handle_event.h_fp = event_handle;
    mqtt_params.handle_event.pcontext = NULL;

    ploragw->pclient = IOT_MQTT_Construct(&mqtt_params);
    if (NULL == ploragw->pclient) {
        log_err("MQTT construct failed");
        return -1;
    }

    // subscribe gateway topic
    rc = subscribe_topics();
    if (rc < 0) {
        log_err("subscribe_topics failed ret = %d", rc);
        goto do_exit;
    }

#if defined(ENABLE_MSG_CACHE)    
    msg_init();
#endif
    // create check file thread
    rc = pthread_create(&thrid_file, NULL, (void * ( *)(void *))thread_file_check, NULL);
    if (0 != rc) {
        log_err("impossible to create check file thread\n");
        goto do_exit;
    }
#if defined(ENABLE_MSG_CACHE)
    rc = pthread_create(&thrid_msg_cache, NULL, (void * ( *)(void *))thread_msg_cache, NULL);
       if (0 != rc) {
           log_err("impossible to create msg cache thread\n");
           goto do_exit;
       }
#endif

    #if defined(ENABLE_OTA)
    ploragw->h_ota = IOT_OTA_Init(ploragw->auth_info.product_key, ploragw->auth_info.device_name, ploragw->pclient);
    if (NULL == ploragw->h_ota) {
        log_err("initialize OTA failed");
        goto do_exit;
    }
    // create ota check thread
    rc = pthread_create(&thrid_ota, NULL, (void * ( *)(void *))thread_ota_check, NULL);
    if (0 != rc) {
        log_err("impossible to create ota check thread\n");
        goto do_exit;
    }
    #endif
    
    // publish device info on boot
    publish_deviceinfo_upload();

    HAL_SleepMs(200);
    // publish gw config to nms on boot
    publish_gwconfig_upload();

    HAL_MutexLock(ploragw->check_mutex);
    ploragw->checkCnt = 0;
    HAL_MutexUnlock(ploragw->check_mutex);
 
    while (1) {
        //handle the MQTT packet received from TCP or SSL connection
        IOT_MQTT_Yield(ploragw->pclient, 500);
        HAL_SleepMs(200);

        if (ploragw->checkCnt > MQTT_CONNECT_RESET_CHECK_CNT) {
            log_err("no downlink in %d uplink counts, need restart mqtt client\n", ploragw->checkCnt);
            break;
        }

        #if defined(ENABLE_WATCHDOG)
        if (thread_feeddog_periodically(MQTT_SYMBOL, THRD_ID_MAIN, 60, 180, &watchdog_time_keeper) < 0) {
            log_err("mqtt main thread feeddog failed\n");
        }
        #endif
    }

    #if defined(ENABLE_WATCHDOG)
    /*feed watchdog 180s while mqtt client is quiting . so system will reboot when mqtt client does't reconnect to the server in 180s*/
	#if !defined(ENABLE_ABP_NODES)
    thread_feeddog(MQTT_SYMBOL, THRD_ID_MAIN, 180);
	#else
	if(!lora_ns_server_exist) {
		thread_feeddog(MQTT_SYMBOL, THRD_ID_MAIN, 180);
	}
	#endif
    #endif

do_exit:
    exit_sig = 1;


    HAL_SleepMs(3000);

    unsubscribe_topics();

    #if defined(ENABLE_OTA)
    if (NULL != ploragw->h_ota) {
        IOT_OTA_Deinit(ploragw->h_ota);
        ploragw->h_ota = NULL;
    }
    #endif

    if (NULL != ploragw->pclient) {
        IOT_MQTT_Destroy(&ploragw->pclient);
        ploragw->pclient = NULL;
    }
    
    HAL_SleepMs(200);
    return 0;
}

int main(int argc, char **argv)
{
    int rc = 0;
    char *msg_buf = NULL;
    char *msg_readbuf = NULL;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    memset(ploragw, 0x0, sizeof(iotx_lorogw_t));

    IOT_OpenLog("mqtt");
    IOT_SetLogLevel(IOT_LOG_INFO);

    if (NULL == (ploragw->check_mutex = HAL_MutexCreate())) {
        log_err("create mutex failed");
        goto do_exit;
    }

    #if defined(ENABLE_REMOTE_LOG)
    log_init(FILELOG_MOD_IOTX, LOG_FILE, LOG_LEVEL_INFO, LOG_MOD_VERBOSE);
    if (NULL == (ploragw->log_mutex = HAL_MutexCreate())) {
        log_err("create mutex failed");
        goto do_exit;
    }
    #endif

    #if defined(ENABLE_ABP_NODES)
    if (NULL == (ploragw->abp_mutex = HAL_MutexCreate())) {
        log_err("create mutex failed");
        goto do_exit;
    }
    #endif
#if defined(ENABLE_OTA) && defined(ENABLE_ADVANCED_OTA)
    if (NULL == (ploragw->ota_mutex = HAL_MutexCreate())) {
        log_err("create mutex failed");
        goto do_exit;
    }
#endif
    ploragw->ppub_msg = (char *)HAL_Malloc(MSG_LEN_MAX);
    ploragw->prev_msg = (char *)HAL_Malloc(MSG_LEN_MAX);
    msg_buf = (char *)HAL_Malloc(MSG_LEN_MAX);
    msg_readbuf = (char *)HAL_Malloc(MSG_LEN_MAX);
    if ((NULL == msg_buf) || (NULL == msg_readbuf)
            || (NULL == ploragw->ppub_msg) || (NULL == ploragw->prev_msg)) {
        log_err("malloc mqtt buf error");
        goto do_exit;
    }

    native_exit_sig = 0;

    // create UDP channel for gateway
    ploragw->sock_up = -1;
    ploragw->sock_down = -1;
    rc = create_gw_upd_msg();
    if (0 != rc) {
        log_err("create gw upd channel fail, ret = %d", rc);
        goto do_exit;
    }

    #if defined(ENABLE_ABP_NODES)
    ploragw->native_sock_up = -1;
    ploragw->native_sock_down = -1;
    rc = create_native_upd_msg();
    if (0 != rc) {
        log_err("create native upd channel fail, ret = %d", rc);
        goto do_exit;
    }

    abp_key_init();

    abp_redis_init();
    #endif
#ifdef ENABLE_DBUS_IPC
    rc = mqtt_dbus_setup();
    if(rc < 0) {
        log_err("setup dbus ipc failed!!!\n");
        goto do_exit;
    }
#endif
    while (1) {
        exit_sig = 0;
        mqtt_client(msg_buf, msg_readbuf);
        log_err("mqtt client run error, sleep 3s restart");
        HAL_SleepMs(3000);
    }
    
do_exit:
    native_exit_sig = 1;

    HAL_SleepMs(3000);

    #if defined(ENABLE_ABP_NODES)
    if (-1 != ploragw->native_sock_up) {
        close(ploragw->native_sock_up);
        ploragw->native_sock_up = -1;
    }

    if (-1 != ploragw->native_sock_down) {
        close(ploragw->native_sock_down);
        ploragw->native_sock_down = -1;
    }
    #endif 

    if (-1 != ploragw->sock_up) {
        close(ploragw->sock_up);
        ploragw->sock_up = -1;
    }

    if (-1 != ploragw->sock_down) {
        close(ploragw->sock_down);
        ploragw->sock_down = -1;
    }

    if (NULL != msg_buf) {
        HAL_Free(msg_buf);
    }
    if (NULL != msg_readbuf) {
        HAL_Free(msg_readbuf);
    }
    if (NULL != ploragw->ppub_msg) {
        HAL_Free(ploragw->ppub_msg);
    }
    if (NULL != ploragw->prev_msg) {
        HAL_Free(ploragw->prev_msg);
    }
#ifdef ENABLE_DBUS_IPC
    rc = mqtt_dbus_exit();
    if(rc != LORA_IPC_SUCCESS) {
        log_err("exit from dbus ipc failed!!!");
    }
#endif
    #if defined(ENABLE_REMOTE_LOG)
    if (NULL != ploragw->log_mutex) {
        HAL_MutexDestroy(ploragw->log_mutex);
    }
    log_destroy();
    #endif

    #if defined(ENABLE_ABP_NODES)
    if (NULL != ploragw->abp_mutex) {
        HAL_MutexDestroy(ploragw->abp_mutex);
    }
    #endif

    #if defined(ENABLE_OTA)  && defined(ENABLE_ADVANCED_OTA)
    if (NULL != ploragw->ota_mutex) {
        HAL_MutexDestroy(ploragw->ota_mutex);
    }
    #endif
    if (NULL != ploragw->check_mutex) {
        HAL_MutexDestroy(ploragw->check_mutex);
    }

    IOT_DumpMemoryStats(IOT_LOG_DEBUG);
    IOT_CloseLog();

    log_info("exit");

    return 0;
}

