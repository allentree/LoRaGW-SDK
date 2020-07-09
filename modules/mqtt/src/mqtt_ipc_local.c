#include "mqtt_ipc_local.h"
#ifdef ENABLE_DBUS_IPC
#include "mqtt_interface_export.h"
#ifdef ENABLE_ADVANCED_OTA
#include "update_interface_export.h"
#include "iot_export.h"
#endif

#if defined(ENABLE_MONITOR)
#include "monitor_interface_export.h"
#endif

#include "sysconfig.h"
#include "mqtt_global.h"

#ifdef ENABLE_ADVANCED_OTA
int ota_report_ota_process_signal(DBusConnection * conn, DBusMessage *pmsg);
int ota_report_version_call(DBusConnection * conn, DBusMessage *pmsg);
#endif

#ifdef ENABLE_MONITOR
int mqtt_gwmp_uplink_signal(DBusConnection * conn, DBusMessage *pmsg);
#endif

dbus_message_callback_st call_config[] = {
    #ifdef ENABLE_ADVANCED_OTA
    {
        SIGNAL_REPORT_PROCESS,
        ota_report_ota_process_signal,
    },
    {
        METHOD_REPORT_VER,
        ota_report_version_call,
    },
    #endif
    #ifdef ENABLE_MONITOR
    {
        SIGNAL_GWMP_UPLINK,
        mqtt_gwmp_uplink_signal,
    },
    #endif
};


extern iotx_lorogw_t g_iotx_loragw;

#if defined(ENABLE_MONITOR)
extern int loragw_ipc_monitor_msg_uplink_send(const char * msg_body);
#endif

static int check_and_abort(DBusError *error)
{
    if (!dbus_error_is_set(error))
    {
        return 0;
    }

    log_err( "DBus error:%s!",error->message);
    dbus_error_free(error);
    return -1;
}
int mqtt_dbus_setup()
{
    int ret = -1;
    dbus_params_st dbus_config = {
        MQTT_WELL_KNOWN_NAME,
        MQTT_OBJECT_NAME,
        MQTT_INTERFACE_NAME,
    };
    ret = loragw_ipc_setup(&dbus_config);
    if(ret < 0) {
        log_err("loragw ipc setup failed!!!\n");
        return ret;
    }
    int count = sizeof(call_config)/sizeof(call_config[0]);
    int i = 0;

    for(i = 0 ; i < count ; i++) {
        ret = loragw_ipc_setup_msg_callback(call_config[i].name, call_config[i].call );
        if(ret < 0) {
            log_err("register %s 's callback failed , ret code %d!!", call_config[i].name, ret);
            break;
        }
    }
    if(ret < 0) {
        loragw_ipc_exit();
    }
    return ret;

}
int mqtt_dbus_exit()
{
    return loragw_ipc_exit();
}
#ifdef ENABLE_ADVANCED_OTA
extern int need_reinit_ota;
int ota_report_ota_process_signal(DBusConnection * conn, DBusMessage *pmsg)
{
    DBusError error;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    if(!conn || !pmsg) {
        return LORA_IPC_ERROR_INVALID_PARAM;
    }
    dbus_error_init(&error);
    int state = -5;
    const char * process_word = NULL;
    dbus_message_get_args(pmsg, &error,
									DBUS_TYPE_INT32,
									&state,
									DBUS_TYPE_STRING,
									&process_word,
									DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) 
    {
        dbus_error_free(&error);
        return LORA_IPC_ERROR_INVALID_DATA;
    }
    HAL_MutexLock(ploragw->ota_mutex);
    if(ploragw->h_ota) {
        IOT_OTA_ReportProgress(ploragw->h_ota, state, process_word);
        if(state < 0 || state == 100) {
            log_info("update finshed : need reinit ota context!");
            need_reinit_ota = 1;
        }
    }
    HAL_MutexUnlock(ploragw->ota_mutex);

    return LORA_IPC_SUCCESS;
}

int ota_report_version_call(DBusConnection * conn, DBusMessage *pmsg)
{
    int ret = 0;
    DBusMessage *reply = NULL;
    DBusError error;
    char *version = NULL;
    char *response = NULL;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    if(!conn || !pmsg) {
        log_err("params error!!!\n");
        return LORA_IPC_ERROR_INVALID_PARAM;
    }

    dbus_error_init(&error);

    reply = dbus_message_new_method_return(pmsg);

    dbus_message_get_args(pmsg, &error, DBUS_TYPE_STRING, &version, DBUS_TYPE_INVALID);
    if (0 != check_and_abort(&error))
    {
        log_err( "dbus_message_get_args() failed");
        goto error1;
    }
    log_info("OTA info, report current version: %s", version);

    HAL_MutexLock(ploragw->ota_mutex);
    
    if (NULL == ploragw->h_ota) {
        log_err("ota context not init!");
        HAL_MutexUnlock(ploragw->ota_mutex);
        goto error1;
    }

    ret = IOT_OTA_ReportVersion(ploragw->h_ota, version);
    if (0 != ret) {
        log_err("report OTA version failed, ret: %d\n", ret);
        HAL_MutexUnlock(ploragw->ota_mutex);
        goto error1;
    }
    HAL_MutexUnlock(ploragw->ota_mutex);
    
    log_info("OTA info, report current version: %s successful", version);
    response = SUCCESS_WORD;
    dbus_message_append_args(reply, DBUS_TYPE_STRING, &response, DBUS_TYPE_INVALID);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
    return LORA_IPC_SUCCESS;
error1:
    response = FAILED_WORD;
    dbus_message_append_args(reply, DBUS_TYPE_STRING, &response, DBUS_TYPE_INVALID);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
    return LORA_IPC_SUCCESS;
}

int ota_notify_update_file_info(const char *version, const char * md5sum, unsigned int size, char *file_path)
{
    int ret = 0;
    DBusMessage *message = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;

    dbus_error_init(&error);
    if(!version || !md5sum || !size || !file_path)
    {
        return LORA_IPC_ERROR_INVALID_PARAM;
    }
    message = dbus_message_new_method_call(UPDATE_WELL_KNOWN_NAME,UPDATE_OBJECT_NAME, UPDATE_INTERFACE_NAME, METHOD_OTA_START );
    if (message == NULL)
    {
        log_err("alloc dbus message failed!!!\n");
        return LORA_IPC_ERROR_IO;
    }
    dbus_message_append_args(message,
                            DBUS_TYPE_STRING, &version,
                            DBUS_TYPE_STRING, &md5sum,
                            DBUS_TYPE_UINT32, &size,
                            DBUS_TYPE_INVALID);

    msgReply = (DBusMessage *)loragw_ipc_send_with_reply_and_block((void *)message, 3000, (void*)&error);
    dbus_message_unref(message);

    if (dbus_error_is_set(&error)) 
    {
        if(dbus_error_has_name(&error, DBUS_ERROR_NO_REPLY)) {
            ret = LORA_IPC_ERROR_TIME_OUT;
            log_err("do not get reply!!");
        }
        else {
            ret = LORA_IPC_ERROR_DBUS_SEND;
            log_err("do not get reply!!");
        }
        dbus_error_free(&error);
        return ret;
    }
    if(!msgReply)
    {
        log_err("did not get the reply message!!!\n");
        return LORA_IPC_ERROR_TIME_OUT;
    }

    const char *chr_reply_msg = NULL;
    const char *filepath = NULL;
    dbus_message_get_args(msgReply, &error, DBUS_TYPE_STRING, &chr_reply_msg, DBUS_TYPE_STRING, &filepath, DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) 
    {
        log_err("can not get response code from reply message!!!\n");
        dbus_error_free(&error);
        dbus_message_unref(msgReply);
        return LORA_IPC_ERROR_INVALID_DATA;
    }
    
    if(strcmp(chr_reply_msg, SUCCESS_WORD) == 0)
    {
        //dbus_error_free(&error);
        log_info("start download ota files to path : %s !", filepath);
        strcpy(file_path, filepath);
        dbus_message_unref(msgReply);
        ret = LORA_IPC_SUCCESS;
    }
    else
    {
        //dbus_error_free(&error);
        dbus_message_unref(msgReply);
        ret = LORA_IPC_ERROR_INVALID_DATA;
    }
    return ret;
}


int ota_notify_update_download_result(int result, int filesize)
{
    int ret = 0;
    DBusMessage *message = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;
    const char * result_word = NULL;

    dbus_error_init(&error);
    if(result < 0) {
        result_word = FAILED_WORD;
    }
    else {
        result_word = SUCCESS_WORD;
    }
    message = dbus_message_new_method_call(UPDATE_WELL_KNOWN_NAME,UPDATE_OBJECT_NAME, UPDATE_INTERFACE_NAME, METHOD_OTA_SIGN_CHECK );
    if (message == NULL)
    {
        log_err("alloc dbus message failed!!!\n");
        return LORA_IPC_ERROR_IO;
    }
    dbus_message_append_args(message,
                            DBUS_TYPE_STRING, &result_word,
                            DBUS_TYPE_INT32, &filesize,
                            DBUS_TYPE_INVALID);

    msgReply = (DBusMessage *)loragw_ipc_send_with_reply_and_block((void *)message, 2000, (void*)&error);
    dbus_message_unref(message);

    if (dbus_error_is_set(&error)) 
    {
        if(dbus_error_has_name(&error, DBUS_ERROR_NO_REPLY))
            ret = LORA_IPC_ERROR_TIME_OUT;
        else
            ret = LORA_IPC_ERROR_DBUS_SEND;
        dbus_error_free(&error);
        return ret;
    }
    if(!msgReply)
    {
        log_err("did not get the reply message!!!\n");
        return LORA_IPC_ERROR_TIME_OUT;
    }

    const char *chr_reply_msg = NULL;
    const char *failed_word = NULL;
    dbus_message_get_args(msgReply, &error, DBUS_TYPE_STRING, &chr_reply_msg, DBUS_TYPE_STRING, &failed_word, DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) 
    {
        log_err("can not get response code from reply message!!!\n");
        dbus_error_free(&error);
        dbus_message_unref(msgReply);
        return LORA_IPC_ERROR_INVALID_DATA;
    }
    
    if(strcmp(chr_reply_msg, SUCCESS_WORD) == 0)
    {
        //dbus_error_free(&error);
        //log_info("start download ota files to path : %s !", filepath);
        dbus_message_unref(msgReply);
        ret = LORA_IPC_SUCCESS;
    }
    else
    {
        //dbus_error_free(&error);
        log_err("update return %s : %s!", chr_reply_msg, failed_word);
        dbus_message_unref(msgReply);
        ret = LORA_IPC_ERROR_INVALID_DATA;
    }
    return ret;
}

int mqtt_notify_update_checkout_result(int result, const char *msg)
{
    static int notified = 0;
    const char * state = NULL;
    const char * module = NULL;
    if(!msg )
        return LORA_IPC_ERROR_INVALID_PARAM;
    if(notified > 10) {
        return 0;
    }
        
    DBusMessage *message = dbus_message_new_signal(MQTT_OBJECT_NAME, MQTT_INTERFACE_NAME,
                                  SIGNAL_UPDATE_CHECKOUT);
    if(!message) {
        return LORA_IPC_ERROR_NO_MEM;
    }
    dbus_message_set_destination(message, UPDATE_WELL_KNOWN_NAME);
    if(result < 0) {
        state = FAILED_WORD;
    }
    else {
        state = SUCCESS_WORD;
    }
    module = "mqtt";
    dbus_message_append_args(message, DBUS_TYPE_STRING, &state, DBUS_TYPE_STRING,
                             &module, DBUS_TYPE_STRING , &msg, DBUS_TYPE_INVALID);

    if (FALSE == loragw_ipc_send((void *)message, NULL)) {
        dbus_message_unref(message);
        return LORA_IPC_ERROR_IO;
    }
    log_info("report %s state %s with msg %s !", module, state, msg);

    notified++;
    dbus_message_unref(message);
    return LORA_IPC_SUCCESS;

}
#endif
#if defined(ENABLE_MONITOR)
int mqtt_gwmp_uplink_signal(DBusConnection * conn, DBusMessage *pmsg)
{
    DBusError error;
    //DBusMessageIter arg;
    iotx_lorogw_t *ploragw = &g_iotx_loragw;
    if(!conn || !pmsg) {
        return LORA_IPC_ERROR_INVALID_PARAM;
    }
    dbus_error_init(&error);
    char *msg_body = NULL;
    //int byte_nb = 0;

    msg_body = NULL;

    const char * src_interface = dbus_message_get_interface(pmsg);
    if(!src_interface) {
        return LORA_IPC_ERROR_INVALID_DATA;
    }

    if(strcmp(src_interface, MONITOR_INTERFACE_NAME) == 0) {

        dbus_message_get_args(pmsg, &error, DBUS_TYPE_STRING, &msg_body, DBUS_TYPE_INVALID);
        if (dbus_error_is_set(&error)) 
        {
            log_err("can not get response code from reply message!!!\n");
            dbus_error_free(&error);
            return LORA_IPC_ERROR_INVALID_DATA;
        }

        if (msg_body != NULL && ploragw->pclient != NULL) {
            if( loragw_ipc_monitor_msg_uplink_send (msg_body) < 0) {
                return LORA_IPC_ERROR_DBUS_SEND;
            }
            else {
                return LORA_IPC_SUCCESS;
            }
        }
        else {
            return LORA_IPC_ERROR_INVALID_DATA;
        }

    }

    return LORA_IPC_SUCCESS;
}
#endif

#if defined(ENABLE_MONITOR)
int mqtt_notify_monitor_gwmp_downlink_msg(const char * pmsg)
{
    if(!pmsg || strlen(pmsg) == 0 ) {
        return LORA_IPC_ERROR_INVALID_PARAM;
    }

    DBusMessage *message = dbus_message_new_signal(MQTT_OBJECT_NAME, MQTT_INTERFACE_NAME,
                                  MON_ALARM_SIGNAL);
    if(!message) {
        return LORA_IPC_ERROR_NO_MEM;
    }
    dbus_message_set_destination(message, MONITOR_WELL_KNOWN_NAME);

    dbus_message_append_args(message, DBUS_TYPE_STRING, &pmsg, DBUS_TYPE_INVALID);

    if (FALSE == loragw_ipc_send((void *) message, NULL)) {
        dbus_message_unref(message);
        return LORA_IPC_ERROR_IO;
    }
    dbus_message_unref(message);
    return LORA_IPC_SUCCESS;

}

int mqtt_send_monitor_alarm(int alarm_type, const char *pmsg)
{
    mon_alarm_type_t msg_type = (mon_alarm_type_t)alarm_type;
    if(msg_type > MON_ALARM_REBOOT || !pmsg) {

        return LORA_IPC_ERROR_INVALID_PARAM;
    }
    DBusMessage *message = dbus_message_new_signal(MQTT_OBJECT_NAME, MQTT_INTERFACE_NAME,
                                  MON_ALARM_SIGNAL);
    if(!message) {
        return LORA_IPC_ERROR_NO_MEM;
    }
    dbus_message_set_destination(message, MONITOR_WELL_KNOWN_NAME);

    dbus_message_append_args(message,DBUS_TYPE_UINT32, &msg_type, DBUS_TYPE_STRING, &pmsg, DBUS_TYPE_INVALID);

    if (FALSE == loragw_ipc_send((void *) message, NULL)) {
        dbus_message_unref(message);
        return LORA_IPC_ERROR_IO;
    }
    dbus_message_unref(message);
    return LORA_IPC_SUCCESS;

}
#endif

#endif
