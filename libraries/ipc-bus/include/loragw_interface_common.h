#ifndef _UPDATE_DBUS_DEF_H_
#define _UPDATE_DBUS_DEF_H_
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#if defined(ENABLE_REMOTE_LOG)
#include "log.h"
#else
#include <stdio.h>
#endif

#define IPC_COMMON_TAG "IPC_COMMON"

#if defined(ENABLE_REMOTE_LOG)
#define ipc_log_info(fmt, ...)  log_i(IPC_COMMON_TAG, fmt"\n", ##__VA_ARGS__)
#define ipc_log_err(fmt, ...)   log_e(IPC_COMMON_TAG, fmt"\n", ##__VA_ARGS__)
#define ipc_log_fatal(fmt, ...) log_f(IPC_COMMON_TAG, fmt"\n", ##__VA_ARGS__)
#define ipc_log_warn(fmt, ...) log_w(IPC_COMMON_TAG, fmt"\n", ##__VA_ARGS__)
#define ipc_log_debug(fmt, ...) log_d(IPC_COMMON_TAG, fmt"\n", ##__VA_ARGS__)

#else
#define ipc_log_info(fmt, args...)  \
    do { \
        printf(IPC_COMMON_TAG, "INFO: %s|%03d :: ", __func__, __LINE__); \
        printf(fmt, ##args); \
        printf("%s", "\n"); \
    } while(0)

#define ipc_log_err(fmt, args...)  \
        do { \
            printf(IPC_COMMON_TAG, "ERR: %s|%03d :: ", __func__, __LINE__); \
            printf(fmt, ##args); \
            printf("%s", "\n"); \
        } while(0)

#define ipc_log_fatal(fmt, args...)  \
    do { \
        printf(IPC_COMMON_TAG, "FATAL: %s|%03d :: ", __func__, __LINE__); \
        printf(fmt, ##args); \
        printf("%s", "\n"); \
    } while(0)

#define ipc_log_warn(fmt, args...)  \
        do { \
            printf(IPC_COMMON_TAG, "WARN: %s|%03d :: ", __func__, __LINE__); \
            printf(fmt, ##args); \
            printf("%s", "\n"); \
        } while(0)
#define ipc_log_debug(fmt, args...)  \
    do { \
        printf(IPC_COMMON_TAG, "DEBUG: %s|%03d :: ", __func__, __LINE__); \
        printf(fmt, ##args); \
        printf("%s", "\n"); \
    } while(0)

#endif


typedef enum{
	LORA_IPC_SUCCESS = 0,
	LORA_IPC_ERROR_INVALID_PARAM = -1,
    LORA_IPC_ERROR_NO_MEM = -2,
    LORA_IPC_ERROR_BUS_INVALID = -3,
    LORA_IPC_ERROR_IO = -4,
    LORA_IPC_ERROR_INVALID_DATA = -5,
    LORA_IPC_ERROR_TIME_OUT = -6,
	LORA_IPC_ERROR_INVALID_PROCESSID = -7,
	LORA_IPC_ERROR_PROCESS_INVALID_CONFIG = -8,
	LORA_IPC_ERROR_DBUS_ALLOC = -9,
	LORA_IPC_ERROR_DBUS_SEND = -10,
}update_error_et;

#ifndef SUCCESS_WORD
#define SUCCESS_WORD "success"
#endif

#ifndef FAILED_WORD
#define FAILED_WORD "failed"
#endif
/*max number of the message type in dbus-ipc interface  */
#define IPC_MSG_TYPE_MAX 100


#include <dbus/dbus.h>

#ifndef bus_address
/*the dbus address of the system*/
#define bus_address "unix:path=/tmp/var/run/mbusd/mbusd_socket"
#endif



typedef int (* method_signal_call)(DBusConnection * conn, DBusMessage *pmsg);

typedef struct{
    /*the name of the message*/
    const char * name;
    /*callback of the message*/
    method_signal_call call;
}dbus_message_callback_st;

typedef struct {
    /*well-known-name*/
	const char * wkn_name;
    /*object path*/
	const char * obj_path;
    /*interface path*/
	const char * interface_name;
}dbus_params_st;
/**
* @brief setup the dbus-ipc interface.
*
* @param[in] args is a pointer to the #dbus_params_st.
* @return LORA_IPC_SUCCESS: success, others:  failed.
* @see None.
* @note None.
*/
int loragw_ipc_setup(void * args);
/**
* @brief setup the message's callback.
*
* @param[in] msg is the name of message.
* @param[in] callback is the callback function of the msg  .
* @return LORA_IPC_SUCCESS: success, others:  failed.
* @see None.
* @note None.
*/
int loragw_ipc_setup_msg_callback(const char * msg, method_signal_call callback);
/**
* @brief exit from the dbus-ipc interface.
*
* @return LORA_IPC_SUCCESS: success, others:  failed.
* @see None.
* @note None.
*/
int loragw_ipc_exit();
/**
* @brief send a method call in dbus and waitting the reply
* @param[in] message the dbus message
* @param[in] wait_ms : the blocked time
* @param[out] error : the dbus error
* @return NULL: error, others:  the return message.
* @see None.
* @note None.
*/
void* loragw_ipc_send_with_reply_and_block(void * message, int wait_ms, void *error);
/**
* @brief send a ipc message (no blocked)
* @param[in] message the dbus message
* @param[out] serial is the dbus message serial number
* @return flase: failed, true: success.
* @see None.
* @note None.
*/
bool loragw_ipc_send(void * message,  uint32_t *serial);

typedef int (*loragw_ipc_msg_return_callback)(void *message);
/**
* @brief send a method call in dbus and whitout waiting reply
* note: no implement
*/

int loragw_ipc_send_with_reply_noblock(void * message, int wait_ms, void *error, loragw_ipc_msg_return_callback callback);
/**
* @brief request pid of well-known-name
* @param[in] wkn_name is well-known-name that you want query
* @return FFFFFFFF: the well-known-name not exit, others: the pid of the wkn_name .
* @see None.
* @note None.
*/
uint32_t loragw_ipc_request_pid_by_wkn_block(const char * wkn_name);

#endif

