/*
 * _watchdog_dbus.c
 * 用于管理 watchdog 与 dbus 的连接。
 *  Created on: 2017年11月10日
 *      Author: Zhongyang
 */

#include "_watchdog_includes.h"
#include "thread_pool.h"
#include <errno.h>


#ifndef bus_address
    #define bus_address "unix:path=/tmp/var/run/mbusd/mbusd_socket"
#endif

//#define _WATCHDOG_DBUS_DEBUG
static pthread_t g_thread_dbus_dispatcher;
typedef DBusMessage *(*pfunc_dbus_method_call_block_t)(DBusConnection *connection, DBusMessage *message,
        int timeout_milliseconds, DBusError *error);

pfunc_dbus_method_call_block_t pfunc_watchdog_method_call_block = dbus_connection_send_with_reply_and_block;

typedef struct _watchdog_method_call_dispatch_info_tag {
    struct list_head list_node;
    uint32_t serial_id;
    //    pthread_mutex_t mutex;
    pthread_cond_t cond;
    DBusMessage *reply_msg;
} _WatchdogMethodCallDispatchInfo;

int _watchdog_dbus_get_pid_default_timeout_ms = 5000;
int _watchdog_dbus_get_bus_id_default_timeout_ms = 5000;
int _watchdog_dbus_start_service_timeout_ms = 5000;

time_t gt_watchdog_dbus_ping_daemon_timeout_sec = 30;
time_t gt_watchdog_dbus_ping_interval_sec = 5;
time_t gt_last_success_ping_dbus_daemon = 0;

char gstr_daemon_uuid[64] = { 0 };
uint32_t gu_daemon_pid = ~0u;

static DBusConnection *gp_dbus_connection = NULL;
static _WatchdogMethodCallDispatchInfo _watchdog_method_call_dispatch_list, _watchdog_method_call_timeout_list;
static pthread_mutex_t mutex_method_call_dispatchlist, mutex_method_call_timeout_list;
static pthread_t pthread_method_reply_gc;

static void *watchdog_thread_method_reply_gc(void *args);
static void watchdog_sleep(time_t second);

static DBusHandlerResult watchdog_dbus_filter_method_call_dispatcher(DBusConnection *connection, DBusMessage *msg,
        void *user_data);

static void watchdog_sleep(time_t second)
{
    time_t epoch_now = watchdog_time();
    while (watchdog_time() - epoch_now <= second) {
        sleep(1);
    }
}

static _WatchdogMethodCallDispatchInfo *watchdog_dbus_WatchdogMethodCallDispatchInfo_create()
{
    _WatchdogMethodCallDispatchInfo *instance = (_WatchdogMethodCallDispatchInfo *) malloc(sizeof(
                        _WatchdogMethodCallDispatchInfo));
    if (instance) {
        pthread_cond_init(&instance->cond, NULL);
        //        pthread_mutex_init(&instance->mutex, NULL);
        instance->reply_msg = NULL;
        instance->serial_id = 0;
        INIT_LIST_HEAD(&instance->list_node);
    }
    return instance;
}

static void watchdog_dbus_WatchdogMethodCallDispatchInfo_free(_WatchdogMethodCallDispatchInfo *instance)
{
    if (instance) {
        pthread_cond_destroy(&instance->cond);
        //        pthread_mutex_destroy(&instance->mutex);
        if (instance->reply_msg) {
            dbus_message_unref(instance->reply_msg);
            instance->reply_msg = NULL;
        }
        instance->serial_id = 0;
        free(instance);
        instance = NULL;
    }
}

static DBusHandlerResult watchdog_dbus_filter_method_call_dispatcher(DBusConnection *connection, DBusMessage *msg,
        void *user_data)
{
    if ((NULL == msg)) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    int msg_type = dbus_message_get_type(msg);
    uint32_t reply_serial = 0;
    if ((msg_type == DBUS_MESSAGE_TYPE_METHOD_RETURN) || (msg_type == DBUS_MESSAGE_TYPE_ERROR)) {
        reply_serial = dbus_message_get_reply_serial(msg);
    } else {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    _WatchdogMethodCallDispatchInfo *pos, *n;
    DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    //#define _WATCHDOG_DBUS_DEBUG
#if defined _WATCHDOG_DBUS_DEBUG
    const char *msg_interface = dbus_message_get_interface(msg);
    const char *msg_member = dbus_message_get_member(msg);
    const char *msg_sender = dbus_message_get_sender(msg);
    const char *str_msg_type = dbus_message_type_to_string(msg_type);

    log_info( "\r\n"
          "Received Message: \r\n"
          "  Type:        %s\r\n"
          "  Sender:      %s\r\n"
          "  Interface:   %s\r\n"
          "  Member:      %s\r\n"
          "  Reply Id:    %d\r\n",
          str_msg_type ? str_msg_type : "** NULL",
          msg_sender ? msg_sender : "** NULL",
          msg_interface ? msg_interface : "** NULL",
          msg_member ? msg_member : "** NULL",
          reply_serial);
#endif

    pthread_mutex_lock(&mutex_method_call_dispatchlist);
    list_for_each_entry_safe(pos, n, &_watchdog_method_call_dispatch_list.list_node, list_node) {
        if (reply_serial == pos->serial_id) {
            //            log_debug( "Dispatch found: serial_id=%d, reply_id=%d\r\n", pos->serial_id, reply_serial);
            pos->reply_msg = dbus_message_ref(msg);
            pthread_cond_signal(&pos->cond);
            ret = DBUS_HANDLER_RESULT_HANDLED;
        }
    }
    pthread_mutex_unlock(&mutex_method_call_dispatchlist);

    if (DBUS_HANDLER_RESULT_NOT_YET_HANDLED == ret) {
        log_warn( "Dispatch missed: serial_id=%d, reply_id=%d\r\n", pos->serial_id, reply_serial);
    }

    return ret;
}

DBusMessage *watchdog_dbus_method_send_reply_and_block(DBusConnection *connection,
        DBusMessage *message,
        int timeout_milliseconds,
        DBusError *error)
{
    // 怀疑 dbus_pending_call_block 机制有问题，使用 cond_wait 替代。
    // 与 watchdog_dbus_filter_method_call_dispatcher 配合，通过 dispatcher 队列传递消息；
    // 超时的消息丢到 timeout 队列中，等待 gc 回收。
    int ret = 0;
    _WatchdogMethodCallDispatchInfo *dispatch_info = watchdog_dbus_WatchdogMethodCallDispatchInfo_create();
    if (NULL == dispatch_info) {
        // .const_message 默认为 1，此时 dbus_error_free 不执行 dbus_free 释放内存。
        error->name = "iot.gateway.watchdog.send_reply_block";
        error->message = "Can not allocate memory.";
        return NULL; // NO MEMORY ERROR;
    }

    //    pthread_mutex_lock(&dispatch_info->mutex);

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += timeout_milliseconds / 1000;
    timeout.tv_nsec += (timeout_milliseconds % 1000) * 1000000;
    timeout.tv_sec += (timeout.tv_nsec) / 1000000000;
    timeout.tv_nsec %= 1000000000;

    // 由 filter 准备 reply_msg
    pthread_mutex_lock(&mutex_method_call_dispatchlist);
    list_add_tail(&dispatch_info->list_node, &_watchdog_method_call_dispatch_list.list_node);
    ret = dbus_connection_send(connection, message, &dispatch_info->serial_id);
    if ( !ret ) {
        list_del(&dispatch_info->list_node);
        watchdog_dbus_WatchdogMethodCallDispatchInfo_free(dispatch_info);
        dispatch_info = NULL;
        pthread_mutex_unlock(&mutex_method_call_dispatchlist);
        return NULL;
    }
    dbus_connection_flush(connection);
    //    log_debug( "Message sent, with serial id=%d.\n", dispatch_info->serial_id);
    ret = pthread_cond_timedwait(&dispatch_info->cond, &mutex_method_call_dispatchlist, &timeout);
    //    log_debug( "condition fired.\n");
    list_del(&dispatch_info->list_node);
    //    log_debug( " node removed, preparing for method return, cond wait ret = %d.\n", ret);
    pthread_mutex_unlock(&mutex_method_call_dispatchlist);

    if (0 != ret) {
#if 0
        // 如果超时但其实匹配到了数据的话，按照未超时处理。
        if ((dispatch_info->reply_msg)
            && (dispatch_info->serial_id == dbus_message_get_reply_serial(dispatch_info->reply_msg))) {
            DBusMessage *ret_msg = dbus_message_ref(dispatch_info->reply_msg);
            watchdog_dbus_WatchdogMethodCallDispatchInfo_free(dispatch_info);
            dispatch_info = NULL;
            return ret_msg;
        }
#endif
        // 发生任何错误，丢给 GC 处理。
        pthread_mutex_lock(&mutex_method_call_timeout_list);
        list_add(&dispatch_info->list_node, &_watchdog_method_call_timeout_list.list_node);
        pthread_mutex_unlock(&mutex_method_call_timeout_list);

        // 超时
        // .const_message 默认为 1，此时 dbus_error_free 不执行 dbus_free 释放内存。
        if (ETIMEDOUT == ret) {
            error->name = "iot.gateway.watchdog.send_reply_block";
            error->message = "Wait Timed out";
        } else {
            error->name = "iot.gateway.watchdog.send_reply_block";
            error->message = "Unknown error.";
        }

        return NULL;
    }

    // 正常
    DBusMessage *ret_msg = dbus_message_ref(dispatch_info->reply_msg);
    watchdog_dbus_WatchdogMethodCallDispatchInfo_free(dispatch_info);
    dispatch_info = NULL;

    return ret_msg;
}

void *watchdog_thread_dbus_daemon_watcher(void *args)
{
    while (1) {
        if (WATCHDOG_ERROR_SUCEESS == watchdog_dbus_ping_daemon_block(gstr_daemon_uuid)) {
            gt_last_success_ping_dbus_daemon = watchdog_time();
        }
        usleep(1000000);
        if (g_signal_require_exit == SIGNAL_REQUIRE_EXIT_VALID) {
            return NULL;
        }
    }

    return NULL;
}

int watchdog_dbus_ping_daemon_block(char *bus_uuid)
{
    DBusError dbus_error;
    dbus_error_init(&dbus_error);
#ifdef DBUS_SUPPORT_SERVER_PID
    uint32_t pid = watchdog_dbus_request_pid_block("org.freedesktop.DBus");
    if ((((~0u) != pid) && ((~0u) != gu_daemon_pid)) && (pid != gu_daemon_pid)) {
		/*
        if (0 != kill(gu_daemon_pid, 0) && (ESRCH == errno)) {

        }
		*/
		gu_daemon_pid = pid;
		gt_last_success_ping_dbus_daemon = watchdog_time();
		return WATCHDOG_ERROR_SUCEESS;

    }
	if ((~0u) == pid) {
		
		return WATCHDOG_ERROR_IO;
	}
#else
    // org.freedesktop.DBus.
    DBusMessage *mc_getbusid = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS,
                               "GetId");
    if (NULL == mc_getbusid) {
        return WATCHDOG_ERROR_NO_MEM;
    }
    DBusMessage *mc_ret = pfunc_watchdog_method_call_block(gp_dbus_connection,
                          mc_getbusid,
                          _watchdog_dbus_get_bus_id_default_timeout_ms,
                          &dbus_error);
    dbus_message_unref(mc_getbusid);
    if (dbus_error_is_set(&dbus_error)) {
        log_err(
              "Method Call failed: GetId().\r\n"
              "    Error name:    %s\r\n"
              "    Error Message: %s\r\n",
              dbus_error.name, dbus_error.message);
        dbus_error_free(&dbus_error);
        if (mc_ret) {
            dbus_message_unref(mc_ret);
        }
        return WATCHDOG_ERROR_IO;
    }

    if (NULL == mc_ret) {
        log_err( "Method Call failed: GetId(). Return message is NULL\r\n");
        dbus_error_free(&dbus_error);
        return WATCHDOG_ERROR_IO;
    }

    const char *str_uuid = NULL;
    dbus_message_get_args(mc_ret, &dbus_error, DBUS_TYPE_STRING, &str_uuid, DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&dbus_error)) {
        log_err(
              "Unable to get bus id:\r\n"
              "    Error name:    %s\r\n"
              "    Error Message: %s\r\n",
              dbus_error.name,
              dbus_error.message);
        dbus_error_free(&dbus_error);
        if (mc_ret) {
            dbus_message_unref(mc_ret);
        }
        return WATCHDOG_ERROR_UNKNOWN;
    }

    if (bus_uuid) {
        strcpy(bus_uuid, str_uuid);
    }

    dbus_message_unref(mc_ret);
#endif
    return WATCHDOG_ERROR_SUCEESS;
}

int watchdog_dbus_send_terminate_signal(WatchdogProcess *process, WatchdogThread *thread, int32_t countdown)
{
    if (NULL == process) {
        return 1;
    }
    DBusError dbus_error;
    int return_code = 0;
    dbus_error_init(&dbus_error);

    DBusMessage *signal_terminate = dbus_message_new_signal(WATCHDOG_DBUS_OBJ_PATH,
                                    WATCHDOG_DBUS_INTERFACE,
                                    WATCHDOG_DBUS_SIGNAL_OUT_TERMINATE);
    if (signal_terminate) {
        dbus_message_set_destination(signal_terminate, process->BusUniqueName);
        dbus_message_set_auto_start(signal_terminate, FALSE);

        dbus_message_append_args(signal_terminate,
                                 DBUS_TYPE_STRING,
                                 &thread->WellKnownName,
                                 DBUS_TYPE_STRING,
                                 &thread->UUID,
                                 DBUS_TYPE_INT32,
                                 &countdown,
                                 DBUS_TYPE_INVALID);

        return_code = dbus_connection_send(gp_dbus_connection, signal_terminate, NULL);
        dbus_message_unref(signal_terminate);
        dbus_connection_flush(gp_dbus_connection);
    }
    return return_code ? WATCHDOG_ERROR_SUCEESS : WATCHDOG_ERROR_IO;
}

uint32_t watchdog_dbus_request_pid_block(const char *bus_connection_name)
{
    uint32_t pid_ret = ~(0u);

    if (NULL == bus_connection_name) {
        return pid_ret;
    }
    DBusError dbus_error;
    dbus_error_init(&dbus_error);

    DBusMessage *mc_getpid = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
                             DBUS_PATH_DBUS,
                             DBUS_INTERFACE_DBUS,
                             "GetConnectionUnixProcessID");

    if (NULL == mc_getpid) {
        log_err( "Unable to get method_call.\r\n");
        return pid_ret;
    }

    dbus_message_append_args(mc_getpid, DBUS_TYPE_STRING, &bus_connection_name, DBUS_TYPE_INVALID);
    DBusMessage *mc_ret = pfunc_watchdog_method_call_block(gp_dbus_connection,
                          mc_getpid,
                          _watchdog_dbus_get_pid_default_timeout_ms,
                          &dbus_error);
    dbus_message_unref(mc_getpid);
    if (dbus_error_is_set(&dbus_error)) {
        log_err(
              "Method Call failed: GetConnectionUnixProcessID(bus_name).\r\n"
              "Error name:    %s\r\n"
              "Error Message: %s\r\n",
              dbus_error.name, dbus_error.message);
        dbus_error_free(&dbus_error);
        if (mc_ret) {
            dbus_message_unref(mc_ret);
        }
        return pid_ret;
    }

    if (NULL == mc_ret) {
        return pid_ret;
    }

    if (dbus_message_get_type(mc_ret) == DBUS_MESSAGE_TYPE_ERROR) {
        const char *dbus_error_ret_string;
        dbus_message_get_args(mc_ret, &dbus_error, DBUS_TYPE_STRING, &dbus_error_ret_string, DBUS_TYPE_INVALID);
        if (dbus_error_is_set(&dbus_error)) {
            log_err(
                  "  Unable to get returned error:\r\n"
                  "  Error name:    %s\r\n"
                  "  Error Message: %s\r\n",
                  dbus_error.name,
                  dbus_error.message);
            dbus_error_free(&dbus_error);
        }
        log_err( "  Got error message: %s\r\n", dbus_error_ret_string);
    } else if (dbus_message_get_type(mc_ret) == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
        dbus_message_get_args(mc_ret, &dbus_error, DBUS_TYPE_UINT32, &pid_ret, DBUS_TYPE_INVALID);
        if (dbus_error_is_set(&dbus_error)) {
            log_err(
                  "  Unable to get returned message:\r\n"
                  "  Error name:    %s\r\n"
                  "  Error Message: %s\r\n",
                  dbus_error.name,
                  dbus_error.message);
            dbus_error_free(&dbus_error);
        }
    }

    dbus_message_unref(mc_ret);
    return pid_ret;
}

int watchdog_dbus_uninit()
{
    if (NULL != gp_dbus_connection) {
        dbus_connection_unref(gp_dbus_connection);
        gp_dbus_connection = NULL;
    }
    pthread_join(pthread_method_reply_gc, NULL);
    pthread_join(g_thread_dbus_dispatcher, NULL);
    return 0;
}

int watchdog_dbus_init_default()
{
    pfunc_watchdog_method_call_block = dbus_connection_send_with_reply_and_block;
    DBusError dbus_error;
    dbus_error_init(&dbus_error);

    int ret = watchdog_dbus_init_open_connection();
    if (WATCHDOG_ERROR_SUCEESS != ret) {
        return ret;
    }

    while (dbus_bus_name_has_owner(gp_dbus_connection, WATCHDOG_DBUS_BUS_WELL_KNOWN_NAME, &dbus_error)) {
        struct timespec tm_term = {
            .tv_sec = 0,
            .tv_nsec = 10 * 1000 * 1000,
        };
        pid_t pid = watchdog_dbus_request_pid_block(WATCHDOG_DBUS_BUS_WELL_KNOWN_NAME);
        if ((pid != ~(0ul)) && (pid != getpid())) {
            kill(pid, SIGKILL);
        }
    }
    ret = watchdog_dbus_init_request_well_known_name();

    pfunc_watchdog_method_call_block = watchdog_dbus_method_send_reply_and_block;
    if( pthread_create(&g_thread_dbus_dispatcher, NULL, watchdog_thread_dbus_dispatcher, NULL) != 0 ) {
        log_err( "pthread create failed!!!");
        return WATCHDOG_ERROR_IO;
    }

    return ret;
}

int watchdog_dbus_init_open_connection()
{
    int rc = -1;
    if (FALSE == dbus_threads_init_default()) {
        return WATCHDOG_ERROR_NO_MEM;
    }
    DBusError dbus_error;
    dbus_error_init(&dbus_error);
#ifdef WATCHDOG_DEBUG_DBUS_USE_SESSION
    gp_dbus_connection = dbus_bus_get(DBUS_BUS_SESSION, &dbus_error);
#else
    gp_dbus_connection = dbus_connection_open(bus_address, &dbus_error);
#endif
    if (dbus_error_is_set(&dbus_error)) {
        log_err(WATCHDOG_TAG "-DBUS",
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

    dbus_bool_t dbus_ret = dbus_bus_register(gp_dbus_connection, &dbus_error);
    if ((FALSE == dbus_ret) || (dbus_error_is_set(&dbus_error))) {
        log_err(WATCHDOG_TAG "-DBUS", "Unable to register dbus.");
        if (dbus_error_is_set(&dbus_error)) {
            log_err(WATCHDOG_TAG "-DBUS", "DBusError Name: %s, Message: %s", dbus_error.name, dbus_error.message);
            dbus_error_free(&dbus_error);
        }
        return WATCHDOG_ERROR_IO;
    }

    pthread_mutex_init(&mutex_method_call_timeout_list, NULL);
    pthread_mutex_init(&mutex_method_call_dispatchlist, NULL);

    INIT_LIST_HEAD(&_watchdog_method_call_timeout_list.list_node);
    INIT_LIST_HEAD(&_watchdog_method_call_dispatch_list.list_node);

    watchdog_dbus_add_filter(watchdog_dbus_filter_method_call_dispatcher);

    rc = pthread_create(&pthread_method_reply_gc, NULL, watchdog_thread_method_reply_gc, NULL);
    if( rc != 0) {
        log_err( "pthread create failed!!!" );
        return WATCHDOG_ERROR_IO;
    }
    log_info(WATCHDOG_TAG "-DBUS", "DBus connection opened without well known name.\n");
    return WATCHDOG_ERROR_SUCEESS;
}

int watchdog_dbus_init_request_well_known_name()
{
    DBusError dbus_error;
    dbus_error_init(&dbus_error);

    int req_result = dbus_bus_request_name(gp_dbus_connection,
                                           WATCHDOG_DBUS_BUS_WELL_KNOWN_NAME,
                                           DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                           &dbus_error);
    if (req_result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        log_err(WATCHDOG_TAG "-DBUS",
              "Well known name has been registered.\r\n"
              "Name:    %s\r\n"
              "Message: %s\r\n",
              dbus_error.name, dbus_error.message);
        if (dbus_error_is_set(&dbus_error)) {
            dbus_error_free(&dbus_error);
        }
        return WATCHDOG_ERROR_IO;
    }
    log_debug( "Name requested: %s\r\n", WATCHDOG_DBUS_BUS_WELL_KNOWN_NAME);

    return WATCHDOG_ERROR_SUCEESS;
}

int watchdog_dbus_add_filter(DBusHandleMessageFunction handler)
{
    if (NULL == handler) {
        return WATCHDOG_ERROR_INVALID_PARAM;
    }
    if (dbus_connection_add_filter(gp_dbus_connection, handler, NULL, NULL)) {
        return WATCHDOG_ERROR_SUCEESS;
    }
    return WATCHDOG_ERROR_UNKNOWN;
}

void *watchdog_thread_dbus_dispatcher(void *args)
{
    while (dbus_connection_read_write_dispatch(gp_dbus_connection, 200)) {
        if (g_signal_require_exit == SIGNAL_REQUIRE_EXIT_VALID) {
            return NULL;
        }
    }
    return NULL;
}

int watchdog_dbus_start_service_by_name_block(const char *well_known_name)
{
    if (NULL == well_known_name) {
        return WATCHDOG_ERROR_INVALID_PARAM;
    }

    if (NULL == gp_dbus_connection) {
        watchdog_dbus_init_default();
    }

    // org.freedesktop.DBus.StartServiceByName
    // UINT32 StartServiceByName (in STRING name, in UINT32 flags)
    DBusMessage *mc_start_service_by_name = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
                                            DBUS_PATH_DBUS,
                                            DBUS_INTERFACE_DBUS,
                                            "StartServiceByName");
    if (NULL == mc_start_service_by_name) {
        log_err( "Unable to get method_call.\r\n");
        return WATCHDOG_ERROR_NO_MEM;
    }

    uint32_t flags = 0u;
    DBusError dbus_error;
    dbus_error_init(&dbus_error);

    dbus_message_append_args(mc_start_service_by_name, DBUS_TYPE_STRING, &well_known_name, DBUS_TYPE_UINT32, &flags,
                             DBUS_TYPE_INVALID);

    DBusMessage *mc_ret = pfunc_watchdog_method_call_block(gp_dbus_connection,
                          mc_start_service_by_name,
                          _watchdog_dbus_start_service_timeout_ms,
                          &dbus_error);
    dbus_message_unref(mc_start_service_by_name);

    if (dbus_error_is_set(&dbus_error)) {
        log_err(
              "Method Call failed: StartServiceByName(well_known_name, flag).\r\n"
              "Error name:      %s\r\n"
              "Error Message:   %s\r\n",
              dbus_error.name, dbus_error.message);
        dbus_error_free(&dbus_error);
        if (mc_ret) {
            dbus_message_unref(mc_ret);
        }
        return WATCHDOG_ERROR_IO;
    }

    if (NULL == mc_ret) {
        return WATCHDOG_ERROR_IO;
    }

    uint32_t start_service_return = 0;
    dbus_message_get_args(mc_ret, &dbus_error, DBUS_TYPE_UINT32, &start_service_return, DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&dbus_error)) {
        log_err(
              "Unable to get result.\r\n"
              "Error name:      %s\r\n"
              "Error Message:   %s\r\n",
              dbus_error.name,
              dbus_error.message);
        dbus_error_free(&dbus_error);
        dbus_message_unref(mc_ret);
        return WATCHDOG_ERROR_IO;
    }

    if (1 == start_service_return) {
        log_info( "DBus daemon returned: DBUS_START_REPLY_SUCCESS\r\n");
    } else if (2 == start_service_return) {
        log_warn( "DBus daemon returned: DBUS_START_REPLY_ALREADY_RUNNING\r\n");

    }
    dbus_message_unref(mc_ret);
    return WATCHDOG_ERROR_SUCEESS;
}

static void *watchdog_thread_method_reply_gc(void *args)
{
    do {
        pthread_mutex_lock(&mutex_method_call_timeout_list);
        if (!list_empty(&_watchdog_method_call_timeout_list.list_node)) {
            _WatchdogMethodCallDispatchInfo *pos, *n;
            list_for_each_entry_safe(pos, n, &_watchdog_method_call_timeout_list.list_node, list_node) {
                log_info( "[GC]: collected: reply_id:%d.\r\n", pos->serial_id);
                list_del(&pos->list_node);
                watchdog_dbus_WatchdogMethodCallDispatchInfo_free(pos);
            }
        }
        pthread_mutex_unlock(&mutex_method_call_timeout_list);
        sleep(2);
        if (g_signal_require_exit == SIGNAL_REQUIRE_EXIT_VALID) {
            return NULL;
        }
    } while (1);

    return NULL;
}

