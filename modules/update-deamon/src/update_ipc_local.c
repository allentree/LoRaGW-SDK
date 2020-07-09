//#include "log.h"
#include "update_ipc_local.h"

#include "update_global.h"
#include "ota_utils.h"
#include "update_interface_export.h"
#include "mqtt_interface_export.h"
#include "pktfwd_interface_export.h"
#if defined(ENABLE_MONITOR)
#include "monitor_interface_export.h"
#endif

extern update_global_st g_update; 

int ota_start_call(DBusConnection * conn, DBusMessage *pmsg);
int ota_sign_and_check_call(DBusConnection * conn, DBusMessage *pmsg);
int ota_request_version_call(DBusConnection * conn, DBusMessage *pmsg);
int ota_checkout_signal(DBusConnection * conn, DBusMessage *pmsg);
//local message call
dbus_message_callback_st call_config[] = {
    {
        METHOD_OTA_START,
        ota_start_call,
    },
    {
        METHOD_OTA_SIGN_CHECK,
        ota_sign_and_check_call,
    },
    {
        SIGNAL_UPDATE_CHECKOUT,
        ota_checkout_signal,
    },   
    {
        METHOD_REQUEST_VER,
        ota_request_version_call,
    }
};


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


int update_dbus_setup()
{
    int ret = -1;
    dbus_params_st dbus_config = {
        UPDATE_WELL_KNOWN_NAME,
        UPDATE_OBJECT_NAME,
        UPDATE_INTERFACE_NAME,
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

int update_dbus_exit()
{
    return loragw_ipc_exit();
}


int update_report_ota_ver_to_server(const char * ver)
{
    int ret = 0;
    DBusMessage *message = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;

    dbus_error_init(&error);
    if(!ver || strlen(ver) == 0)
    {
        return LORA_IPC_ERROR_INVALID_PARAM;
    }

    uint32_t mqtt_pid = loragw_ipc_request_pid_by_wkn_block(MQTT_WELL_KNOWN_NAME);
    if(mqtt_pid == (~0)) {
        log_info("mqtt is not running , we do not enable mqtt service, please try later!!");
        return LORA_IPC_ERROR_BUS_INVALID;
    }
    

    message = dbus_message_new_method_call(MQTT_WELL_KNOWN_NAME,MQTT_OBJECT_NAME, MQTT_INTERFACE_NAME, METHOD_REPORT_VER );
    if (message == NULL)
    {
        log_err("alloc dbus message failed!!!\n");
        return LORA_IPC_ERROR_IO;
    }
    log_info("sending version info : %s to server!!", ver);
    dbus_message_append_args(message,
                            DBUS_TYPE_STRING, &ver,
                            DBUS_TYPE_INVALID);
    msgReply = (DBusMessage *)loragw_ipc_send_with_reply_and_block((void*)message, 2000, (void*)&error);
    dbus_message_unref(message);
    log_info("sent version info : %s to server!!" ,ver);
    if (dbus_error_is_set(&error)) 
    {
        //log_err("dbus send return error %s %s !",error.name, error.message );
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
    dbus_message_get_args(msgReply, &error, DBUS_TYPE_STRING, &chr_reply_msg, DBUS_TYPE_INVALID);
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
/*qurey mqtt&pktfwd&monitor running state by dbus*/
int query_major_process_running_state()
{
    static int mqtt_state = 0;
    static int pktfwd_state = 0;
#if defined(ENABLE_MONITOR)   
    static int monitor_state = 0;
#endif
    if(!mqtt_state) {
        uint32_t mqtt_pid = loragw_ipc_request_pid_by_wkn_block(MQTT_WELL_KNOWN_NAME);
        if(mqtt_pid == (~0)) {
            log_info("mqtt is not running!!");
        }
        else {
            mqtt_state = 1;
        }
    }
    if(!pktfwd_state) {
        uint32_t pktfwd_pid = loragw_ipc_request_pid_by_wkn_block(PKTFWD_WELL_KNOWN_NAME);
        if(pktfwd_pid == (~0)) {
            log_info("pktfwd is not running!!");
        }
        else {
            pktfwd_state = 1;
        }
    }
#if defined(ENABLE_MONITOR)     
    if(!monitor_state) {
        uint32_t monitor_pid = loragw_ipc_request_pid_by_wkn_block(MONITOR_WELL_KNOWN_NAME);
        if(monitor_pid == (~0)) {
            log_info("monitor is not running!!");
        }
        else {
            monitor_state = 1;
        }
    }
#endif
#if defined(ENABLE_MONITOR)
    return (mqtt_state && pktfwd_state && monitor_state);
#else
    return (mqtt_state && pktfwd_state);
#endif

}
int ota_start_call(DBusConnection * conn, DBusMessage *pmsg)
{
    char proj_root_path[FILENAME_MAX + 1] = { 0 };
    int ret = 0;
    DBusMessage *reply = NULL;
    DBusError error;
    
    char *version = NULL;
    char *md5 = NULL;
    unsigned int filesize = 0;

    char *response = NULL;

    if(!conn || !pmsg) {
        log_err("params error!!!\n");
        return LORA_IPC_ERROR_INVALID_PARAM;
    }

    dbus_error_init(&error);

    reply = dbus_message_new_method_return(pmsg);

    if(reply == NULL) {
        return LORA_IPC_ERROR_IO;
    }
    dbus_message_get_args(pmsg, &error, DBUS_TYPE_STRING, &version,DBUS_TYPE_STRING, &md5, DBUS_TYPE_UINT32, &filesize, DBUS_TYPE_INVALID);
    if (0 != check_and_abort(&error))
    {
        log_err( "dbus_message_get_args() failed");
        goto error1;
    }
    log_info("OTA info -> new version in server version : %s, md5sum: %s, file size: %d", version, md5, filesize);
    
    //todo : check the disk's free space
    //download the ota packages to ./
    ret = get_realpath_by_exec_dir(proj_root_path, NULL);
    if(ret < 0 )
    {
        log_err("failed to get project root!!!\n");
        goto error1;
    }
    strcat(proj_root_path , "ota.tar.gz");

    get_ota_state( &g_update.ota_state );
    if(g_update.ota_state == OTA_STATE_IDLE) {
        pthread_mutex_lock(&g_update.lock);
        g_update.ota_download_info.ver = strdup(version);
        g_update.ota_download_info.md5 = strdup(md5);
        g_update.ota_download_info.fileSize = filesize;
        g_update.ota_package.ota_file_path = strdup(proj_root_path);
        pthread_mutex_unlock(&g_update.lock);
        set_ota_state(OTA_STATE_DOWNLOADING);
    }

    response = SUCCESS_WORD;
    dbus_message_append_args(reply, DBUS_TYPE_STRING, &response, DBUS_TYPE_STRING, &(g_update.ota_package.ota_file_path), DBUS_TYPE_INVALID);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
    return 0;
error1:
    response = FAILED_WORD;
    const char *path_tmp = "get message args error";
    dbus_message_append_args(reply, DBUS_TYPE_STRING, &response, DBUS_TYPE_STRING, &path_tmp, DBUS_TYPE_INVALID);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
    return 0;
}


int ota_sign_and_check_call(DBusConnection * conn, DBusMessage *pmsg)
{
    DBusMessage *reply = NULL;
    DBusError error;
    
    char *download_state = NULL;
    int filesize = 0;

    const char *response = NULL;
    const char *filed_word = NULL;

    if(!conn || !pmsg) {
        log_err("params error!!!\n");
        return LORA_IPC_ERROR_INVALID_PARAM;
    }

    dbus_error_init(&error);
    
    reply = dbus_message_new_method_return(pmsg);

    dbus_message_get_args(pmsg, &error, DBUS_TYPE_STRING, &download_state, DBUS_TYPE_INT32, &filesize, DBUS_TYPE_INVALID);
    if (0 != check_and_abort(&error)) {
        log_err( "dbus_message_get_args() failed");
        response = FAILED_WORD;
        filed_word = "failed to get message args";
        goto error1;
    }

    log_info("OTA download , result %s , file size %d", download_state, filesize);

    if(strcmp(download_state, SUCCESS_WORD) == 0) {
        if(filesize != g_update.ota_download_info.fileSize) {
            log_err("download ota file size error!!!");
        }
        pthread_mutex_lock(&g_update.lock);
        g_update.ota_state = OTA_STATE_VERIFIING;
        g_update.is_ota_file_checked = 0;
        g_update.sign_valid = 0;
        g_update.sh_valid = 0;
        pthread_mutex_unlock(&g_update.lock);
    }
    else {
        pthread_mutex_lock(&g_update.lock);
        g_update.ota_state = OTA_STATE_IDLE;
        free((void *)g_update.ota_package.ota_info_path);
        g_update.ota_package.ota_info_path = NULL;
        g_update.is_ota_file_checked = 0;
        g_update.sign_valid = 0;
        g_update.sh_valid = 0;
        g_update.ver_reported = 0;
        pthread_mutex_unlock(&g_update.lock);
    }
    response = SUCCESS_WORD;
    filed_word = "verifing ota packages";
error1:
    //response = FAILED_WORD;
    dbus_message_append_args(reply, DBUS_TYPE_STRING, &response,DBUS_TYPE_STRING, &filed_word , DBUS_TYPE_INVALID);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
    return 0;

}
//state : IOT_OTA_Progress_t
int ota_report_process_state(int state, const char * string)
{
    if( (state < -4 || state > 100) || !string) {
        return LORA_IPC_ERROR_INVALID_PARAM;
    }
    DBusMessage *message = dbus_message_new_signal(UPDATE_OBJECT_NAME, UPDATE_INTERFACE_NAME,
                                  SIGNAL_REPORT_PROCESS);
    if(!message) {
        return LORA_IPC_ERROR_NO_MEM;
    }
    dbus_message_set_destination(message, MQTT_WELL_KNOWN_NAME);

    dbus_message_append_args(message, DBUS_TYPE_INT32, &state, DBUS_TYPE_STRING,
                             &string, DBUS_TYPE_INVALID);

    if (FALSE == loragw_ipc_send((void *) message, NULL)) {
        dbus_message_unref(message);
        return LORA_IPC_ERROR_IO;
    }
    dbus_message_unref(message);
    return LORA_IPC_SUCCESS;
}

int ota_request_version_call(DBusConnection * conn, DBusMessage *pmsg)
{
    DBusMessage *reply = NULL;
    //DBusError error;
    
    //char *download_state = NULL;
    //int filesize = 0;

    if(!conn || !pmsg) {
        log_err("params error!!!\n");
        return LORA_IPC_ERROR_INVALID_PARAM;
    }

    //dbus_error_init(&error);
    
    reply = dbus_message_new_method_return(pmsg);
    dbus_message_append_args(reply, DBUS_TYPE_STRING, &g_update.cur_ota_ver, DBUS_TYPE_INVALID);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);

    pthread_mutex_lock(&g_update.lock);
    g_update.ver_reported = 1;
    pthread_mutex_unlock(&g_update.lock);

    return 0;
}

int ota_checkout_signal(DBusConnection * conn, DBusMessage *pmsg)
{
    DBusError error;
    if(!conn || !pmsg) {
        return LORA_IPC_ERROR_INVALID_PARAM;
    }
    dbus_error_init(&error);
    char * state;
    char * module;
    char * errcode;
    dbus_message_get_args(pmsg, &error,
									DBUS_TYPE_STRING,
									&state,
									DBUS_TYPE_STRING,
									&module,
									DBUS_TYPE_STRING,
									&errcode,
									DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) 
    {
        dbus_error_free(&error);
        return LORA_IPC_ERROR_INVALID_DATA;
    }
    pthread_mutex_lock(&g_update.lock);
    if(strstr(module , "pktfwd")) {
        if(strcmp(state, SUCCESS_WORD) == 0) {
            if(g_update.ota_state == OTA_STATE_CHECKING) {
                g_update.ota_check.pktfwd_check_state = 1;
            }
        }
        else {
            if(g_update.ota_state == OTA_STATE_CHECKING) {
                log_err("pktfwd checkout was failed!!! error : %s!",errcode);
                g_update.ota_check.pktfwd_check_state = 0;
            }
            
        }
    }
    else if(strstr(module , "mqtt")) {
        if(strcmp(state, SUCCESS_WORD) == 0) {
            if(g_update.ota_state == OTA_STATE_CHECKING) {
                g_update.ota_check.mqtt_check_state = 1;
            }
        }
        else {
            if(g_update.ota_state == OTA_STATE_CHECKING) {
                log_err("mqtt checkout was failed!!! error : %s!",errcode);
                g_update.ota_check.mqtt_check_state = 0;
            }
        }
    }
    #if defined(ENABLE_MONITOR) 
    else if(strstr(module , "monitor")) {
        if(strcmp(state, SUCCESS_WORD) == 0) {
            if(g_update.ota_state == OTA_STATE_CHECKING) {
                g_update.ota_check.monitor_check_state = 1;
            }
        }
        else {
            if(g_update.ota_state == OTA_STATE_CHECKING) {
                log_err("mqtt checkout was failed!!! error : %s!",errcode);
                g_update.ota_check.monitor_check_state = 0;
            }
        }
    }
    #endif
    pthread_mutex_unlock(&g_update.lock);
    return LORA_IPC_SUCCESS;
}
