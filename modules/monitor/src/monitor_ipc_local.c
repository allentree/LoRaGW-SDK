#include "monitor_ipc_local.h"
#include "mqtt_interface_export.h"
#ifdef ENABLE_ADVANCED_OTA
#include "update_interface_export.h"
#endif
#include "monitor_interface_export.h"
#include "monitor.h"

int monitor_downlink_gwmp_signal(DBusConnection * conn, DBusMessage *pmsg);
int monitor_process_alarm_signal(DBusConnection * conn, DBusMessage *pmsg);

#define JSON_ALARM_FMT "{\"trap\":{\"warn\":{\"%s\":\"%s\"}}}"
static char g_mon_alarm_gwmp[MAX_ALARM_PAYLOAD_LEN];
static int mon_ipc_send_gwmp_msg(mon_alarm_type_t msg_type, const char *msg_body);

dbus_message_callback_st call_config[] = {
    {
        MON_GWMP_DLINK_SIGNAL,
        monitor_downlink_gwmp_signal,
    },
    {
        MON_ALARM_SIGNAL,
        monitor_process_alarm_signal,
    },
};

int monitor_dbus_setup()
{
    int ret = -1;
    dbus_params_st dbus_config = {
        MONITOR_WELL_KNOWN_NAME,
        MONITOR_OBJECT_NAME,
        MONITOR_INTERFACE_NAME,
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

int monitor_dbus_exit()
{
    return loragw_ipc_exit();
}

int monitor_gwmp_msg_send(const char * pmsg)
{
    if(!pmsg || strlen(pmsg)==0 ) {

        return LORA_IPC_ERROR_INVALID_PARAM;
    }

    DBusMessage *message = dbus_message_new_signal(MONITOR_OBJECT_NAME, MONITOR_INTERFACE_NAME,
                                  SIGNAL_GWMP_UPLINK);
    if(!message) {
        return LORA_IPC_ERROR_NO_MEM;
    }
    dbus_message_set_destination(message, MQTT_WELL_KNOWN_NAME);

    dbus_message_append_args(message, DBUS_TYPE_STRING, &pmsg, DBUS_TYPE_INVALID);

    if (FALSE == loragw_ipc_send((void *) message, NULL)) {
        dbus_message_unref(message);
        return LORA_IPC_ERROR_IO;
    }
    dbus_message_unref(message);
    return LORA_IPC_SUCCESS;

}

int monitor_downlink_gwmp_signal(DBusConnection * conn, DBusMessage *pmsg)
{
    DBusError error;
    if(!conn || !pmsg) {
        return LORA_IPC_ERROR_INVALID_PARAM;
    }
    dbus_error_init(&error);
   
    const char * gwmp_msg = NULL;
    dbus_message_get_args(pmsg, &error,
									DBUS_TYPE_STRING,
									&gwmp_msg,
									DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) 
    {
        dbus_error_free(&error);
        return LORA_IPC_ERROR_INVALID_DATA;
    }

    log_dbg("recv gwmp downlink %s !", gwmp_msg);

    return LORA_IPC_SUCCESS;
}

int monitor_process_alarm_signal(DBusConnection * conn, DBusMessage *pmsg)
{
    DBusError error;
    if(!conn || !pmsg) {
        return LORA_IPC_ERROR_INVALID_PARAM;
    }
    dbus_error_init(&error);
   
    const char * msg_body = NULL;
    uint32_t msg_type = 0;

    dbus_message_get_args(pmsg, &error,
                                    DBUS_TYPE_UINT32,
                                    &msg_type,
									DBUS_TYPE_STRING,
									&msg_body,
									DBUS_TYPE_INVALID);
    if (dbus_error_is_set(&error)) 
    {
        dbus_error_free(&error);
        return LORA_IPC_ERROR_INVALID_DATA;
    }

    if (msg_type != -1 && msg_body != NULL) {
        mon_ipc_send_gwmp_msg((mon_alarm_type_t)msg_type, msg_body);
    }

    return LORA_IPC_SUCCESS;
}


int mon_ipc_send_gwmp_msg(mon_alarm_type_t msg_type, const char *msg_body)
{
    int ret;

    switch (msg_type) {
        case MON_ALARM_SX1301:
            snprintf(g_mon_alarm_gwmp, MAX_ALARM_PAYLOAD_LEN,
                     JSON_ALARM_FMT, "radio", msg_body);
            break;

        case MON_ALARM_REBOOT:
            snprintf(g_mon_alarm_gwmp, MAX_ALARM_PAYLOAD_LEN,
                     JSON_ALARM_FMT, "reboot", msg_body);
            break;

        case MON_ALARM_DMESG:
            snprintf(g_mon_alarm_gwmp, MAX_ALARM_PAYLOAD_LEN,
                     JSON_ALARM_FMT, "system", msg_body);
            break;

        default:
            log_err("msg_type not support!");
            return -1;
    }
    ret = monitor_gwmp_msg_send(g_mon_alarm_gwmp);

    if (ret < 0) {
        log_err("fail to send gwmp alarm msg");
        return -1;
    }

    if (msg_type == MON_ALARM_REBOOT) {
        /* wait for 5s to send msg before reboot */
        sleep(5);
    }

    log_dbg("start to send gwmp msg %s", g_mon_alarm_gwmp);
    return 0;
}

int monitor_send_alarm_interal(int type, const char *pmsg) 
{
    mon_alarm_type_t msg_type = (mon_alarm_type_t)type;
    if(msg_type > MON_ALARM_REBOOT || !pmsg) {

        return -1;
    }
    DBusMessage *message = dbus_message_new_signal(MONITOR_OBJECT_NAME, MONITOR_INTERFACE_NAME,
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

#ifdef ENABLE_ADVANCED_OTA
int monitor_notify_update_checkout_result(int result, const char *msg)
{
    static int notified = 0;
    const char * state = NULL;
    const char * module = NULL;
    if(!msg )
        return LORA_IPC_ERROR_INVALID_PARAM;
    if(notified > 10) {

        return 0;
    }
        
    DBusMessage *message = dbus_message_new_signal(MONITOR_OBJECT_NAME, MONITOR_INTERFACE_NAME,
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
    module = "monitor";
    dbus_message_append_args(message, DBUS_TYPE_STRING, &state, DBUS_TYPE_STRING,
                             &module, DBUS_TYPE_STRING , &msg, DBUS_TYPE_INVALID);

    if (FALSE == loragw_ipc_send((void *)message, NULL)) {
        dbus_message_unref(message);
        return LORA_IPC_ERROR_IO;
    }
    log_info("report %s state %s with msg %s !", module, state, msg);

    notified ++;
    dbus_message_unref(message);
    return LORA_IPC_SUCCESS;

}
#endif