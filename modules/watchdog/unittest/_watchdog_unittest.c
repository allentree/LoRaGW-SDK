/*
 * _watchdog_unittest.c
 *
 *  Created on: 2017年11月15日
 *      Author: Zhongyang
 */

#include "watchdog_dbus_config.h"
#include "_watchdog_macros.h"
#if defined(ENABLE_REMOTE_LOG)
#include "log.h"
#endif
#include "dbus/dbus.h"

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef bus_address
#define bus_address "unix:path=/tmp/var/run/mbusd/mbusd_socket"
#endif

#define WATCHDOG_UNITTEST_TAG               "WATCHDOG-UNITTEST"
#define WATCHDOG_UNITTEST_DBUS_WKN          "iot.gateway.watchdog.unittest"
#define WATCHDOG_UNITTEST_DBUS_INTERFACE    "iot.gateway.watchdog.unittest"
#define WATCHDOG_UNITTEST_DBUS_OBJ_PATH     "/iot/gateway/watchdog/unittest"
#if !defined WATCHDOG_DBUS_SIGNAL_IN_FEEDDOG
#define WATCHDOG_DBUS_SIGNAL_IN_FEEDDOG     "feedDog"
#endif
#if !defined WATCHDOG_DBUS_BUS_WELL_KNOWN_NAME
#define WATCHDOG_DBUS_BUS_WELL_KNOWN_NAME   "iot.gateway.watchdog"
#endif
DBusConnection* gp_dbus_connection = NULL;

#if defined(ENABLE_REMOTE_LOG)
#define log_info(fmt, ...)  log_i(WATCHDOG_UNITTEST_TAG, fmt"\n", ##__VA_ARGS__)
#define log_err(fmt, ...)   log_e(WATCHDOG_UNITTEST_TAG, fmt"\n", ##__VA_ARGS__)
#define log_fatal(fmt, ...) log_f(WATCHDOG_UNITTEST_TAG, fmt"\n", ##__VA_ARGS__)
#define log_warn(fmt, ...) log_w(WATCHDOG_UNITTEST_TAG, fmt"\n", ##__VA_ARGS__)
#define log_debug(fmt, ...) log_d(WATCHDOG_UNITTEST_TAG, fmt"\n", ##__VA_ARGS__)
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
void unittest_signal_handler(int sig)
{
    if (strsignal(sig)) {
        log_err(" Caught SIGNAL: %s, I'm Dying!! ( ´•̥̥̥ω•̥̥̥` )\r\n", strsignal(sig));
    }
}

struct wkn_uuid
{
    char wkn[40];
    char uuid[20];
};


void* test_case10_worker(void* _args)
{
    struct wkn_uuid* arg = (struct wkn_uuid*) _args;
    test_case10(arg->wkn, arg->uuid);
    free(arg);
    return NULL;
}

int test_case10(char* wkn, char* uuid)
{
    int countdown = -1;
    int ret_code;

    while (1) {
        countdown = 5;
        ret_code = dbus_send_feedDog(gp_dbus_connection, wkn, uuid, countdown);
        if( 0 == ret_code )
            log_info(" Message sent with cd=%d\n", countdown);
        else
            log_err(" Unable to send feedDog signal.\n");
        sleep(1);
    }
}

void start_test_case10(int num)
{
    pthread_t threads[num];
    struct wkn_uuid args[num];
    struct timespec thread_interval, thread_interval_remain;
    thread_interval.tv_sec = 0;
    thread_interval.tv_nsec = (1000000000) / num;
    int i = 0; 
    for (i = 0; i < num; ++i) {
        snprintf(args[i].wkn, 40, WATCHDOG_UNITTEST_DBUS_WKN ".%d", i);
        snprintf(args[i].uuid, 20, "%d", i);
        pthread_create(&threads[i], NULL, test_case10_worker, &args[i]);
        nanosleep(&thread_interval, &thread_interval_remain);
    }

    while (1) {
        sleep(1);
    }
}


int init_dbus()
{
    DBusError dbus_error;
    dbus_error_init(&dbus_error);
#ifdef WATCHDOG_DEBUG_DBUS_USE_SESSION
    gp_dbus_connection = dbus_bus_get(DBUS_BUS_SESSION, &dbus_error);
#else
    gp_dbus_connection = dbus_connection_open(bus_address, &dbus_error);
#endif
    if (dbus_error_is_set(&dbus_error)) {
        log_err(
              "Failed to open connection.\r\n"
              "Name:    %s\r\n"
              "Message: %s\r\n",
              dbus_error.name, dbus_error.message);
        dbus_error_free(&dbus_error);
        return WATCHDOG_ERROR_IO;
    }
    if (NULL == gp_dbus_connection) {
        return WATCHDOG_ERROR_IO;
    }

    dbus_bus_register(gp_dbus_connection, &dbus_error);
    if (dbus_error_is_set(&dbus_error)) {
        log_err(
              "Failed to register.\r\n"
              "Name:    %s\r\n"
              "Message: %s\r\n",
              dbus_error.name, dbus_error.message);
        dbus_error_free(&dbus_error);
        return WATCHDOG_ERROR_IO;
    }

    int req_result = dbus_bus_request_name(gp_dbus_connection,
                                           WATCHDOG_UNITTEST_DBUS_INTERFACE,
                                           DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                           &dbus_error);

    if (dbus_error_is_set(&dbus_error)) {
        if (req_result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
            log_err(
                  "Well known name has been registered.\r\n"
                  "Name:    %s\r\n"
                  "Message: %s\r\n",
                  dbus_error.name, dbus_error.message);
        }
        dbus_error_free(&dbus_error);
        return WATCHDOG_ERROR_IO;
    }

    return WATCHDOG_ERROR_SUCEESS;
}


int get_random_bytes(void* dest, int size)
{
    if ((NULL == dest) || (size <= 0))
        return WATCHDOG_ERROR_INVALID_PARAM;

    FILE* random = fopen("/dev/urandom", "r");
    if (random != NULL) {
        if (0 == fread(dest, size, 1, random))
            memset(dest, 0, size);
        fclose(random);
        return WATCHDOG_ERROR_SUCEESS;
    }

    return WATCHDOG_ERROR_IO;
}

int dbus_send_feedDog(DBusConnection* conn, const char* const wkn, const char* const uuid, int countdown)
{
    DBusMessage* signal_feeddog = dbus_message_new_signal(WATCHDOG_UNITTEST_DBUS_OBJ_PATH, WATCHDOG_DBUS_INTERFACE, WATCHDOG_DBUS_SIGNAL_IN_FEEDDOG);
    if (NULL == signal_feeddog)
        return WATCHDOG_ERROR_NO_MEM;
    dbus_message_set_destination(signal_feeddog, WATCHDOG_DBUS_BUS_WELL_KNOWN_NAME);

    int ret_code;
    dbus_message_append_args(signal_feeddog, DBUS_TYPE_STRING, &wkn, DBUS_TYPE_STRING, &uuid, DBUS_TYPE_INT32, &countdown, DBUS_TYPE_INVALID);
    ret_code = dbus_connection_send(gp_dbus_connection, signal_feeddog, NULL);
    dbus_message_unref(signal_feeddog);
    dbus_connection_flush(gp_dbus_connection);
    return (ret_code == TRUE) ? 0 : WATCHDOG_ERROR_IO;
}
static int get_project_root(char* dir)
{
    static char abs_gateway_root[FILENAME_MAX + 1] = "../";
    static int first = 1;

    if (NULL == dir)
        return 1;

    if (first == 1) {
        char rel_gateway_root[FILENAME_MAX + 1];
        int len = readlink("/proc/self/exe", rel_gateway_root, FILENAME_MAX);
        if (len <= 0)
            return 1;
        rel_gateway_root[len] = '\0';
        char* path_end = strrchr(rel_gateway_root, '/');
        if(path_end)
            *path_end = '\0';
        else {
            return 1;
        }
        //strcat(rel_gateway_root, "/../");
        char* real_path = realpath(rel_gateway_root, abs_gateway_root);
        if (NULL == real_path) {
            strcpy(dir, rel_gateway_root);
            return 1;
        }
        first = 0;
    }
    strcpy(dir, abs_gateway_root);

    return 0;
}

int main(int argc, char** argv)
{
    struct sigaction sig_sigchld;
    memset(&sig_sigchld, 0, sizeof(struct sigaction));
    sigemptyset(&sig_sigchld.sa_mask);
    sig_sigchld.sa_handler = unittest_signal_handler;
    sigaction(SIGTERM, &sig_sigchld, NULL);
    int ret = -1; 
	char proj_root_path[FILENAME_MAX + 1] = { 0 };
	
    get_project_root(proj_root_path);
	strcat(proj_root_path,"/");
	strcat(proj_root_path,WATCHDOG_UNITTEST_DBUS_WKN);
#if defined(ENABLE_REMOTE_LOG)	
    ret = log_init(proj_root_path, LOG_FILE, LOG_LEVEL_DEBUG, LOG_MOD_VERBOSE);
    if(ret < 0)
    {
        printf("_watchdong_unittest : log init error!!!\n");
    }
#endif	
	log_info( "running root path %s!\n",proj_root_path );
    if (WATCHDOG_ERROR_IO == init_dbus()) {
        log_err("Unable to open DBusConnection.\r\n");
        return 1;
    }
    /*
     * iot.gateway.watchdog.feedDog (string well_known_name, string uuid, int countdown)
     *  - uuid(well_known_name):    服务的 Well known name，保活模块通过 StartServiceByName 启动这个服务。
     *  - uuid(string):             线程的唯一标识符，保活模块用来记录线程的 countdown
     *  - countdown(int):           倒计时时间，传入 -1 停止守护。
     *                              计划使用“秒”作为单位，毫秒级的精度对调度压力很大。
     *                              （毫秒级的精度可能可以通过 linux kernel module 来减轻系统负荷，
     *                              但是对 linux 的依赖就更强了，移植和兼容性可能有风险（待评估）。
     */

    if (argc >= 3) {
        if (0 == strcmp("case10", argv[1])) {
            int thread_num = 1;
            if (sscanf(argv[2], "%d", &thread_num)) {
                if (thread_num > 1000)
                    thread_num = 1000;
                else if (thread_num <= 0)
                    thread_num = 1;
                start_test_case10(thread_num);
            }
        }
    }


    const char* uuid = "";
    if (argc > 1) {
        uuid = strdup(argv[1]);
    }

    size_t wkn_strlen = strlen(WATCHDOG_UNITTEST_DBUS_WKN) + 2 + strlen(uuid);
    char wkn[strlen(WATCHDOG_UNITTEST_DBUS_WKN) + 2 + strlen(uuid)];

    if (strlen(uuid) != 0) {
        snprintf(wkn, wkn_strlen, "%s.%s", WATCHDOG_UNITTEST_DBUS_WKN, uuid);
    }
    else {
        snprintf(wkn, wkn_strlen, "%s", WATCHDOG_UNITTEST_DBUS_WKN);
    }

    int countdown = 5;
    int ret_code;
    ret_code = dbus_send_feedDog(gp_dbus_connection, wkn, uuid, countdown);
    if (ret_code == WATCHDOG_ERROR_SUCEESS)
        log_info( "message sent! waiting to be killed in 5 secs.\r\n");

    sleep(3);

    countdown = -1;
    ret_code = dbus_send_feedDog(gp_dbus_connection, wkn, uuid, countdown);
    if (ret_code == WATCHDOG_ERROR_SUCEESS)
        log_info("feedDog CANCEL signal sent.\r\n");
    sleep(7);

    countdown = 5;
    ret_code = dbus_send_feedDog(gp_dbus_connection, wkn, uuid, countdown);
    if (ret_code == WATCHDOG_ERROR_SUCEESS) {
        log_info("message sent! waiting to be killed in %d secs.\r\n", countdown);
        while (1) {
            sleep(10);
            log_info( "Yay!! I'm alive!\r\n");
        }
        return WATCHDOG_ERROR_SUCEESS;
    }

    return 0;
}
