#include "pktfwd_ipc_local.h"
#ifdef ENABLE_DBUS_IPC
#include "loragw_interface_common.h"
#if defined(ENABLE_ADVANCED_OTA)
#include "update_interface_export.h"
#endif
#if defined(ENABLE_MONITOR)
#include "monitor_interface_export.h"
#endif
#include "pktfwd_interface_export.h"

/*
dbus_message_callback_st call_config[] = {

};
*/

int pktfwd_ipc_setup()
{
    int ret = -1;
    dbus_params_st dbus_config = {
        PKTFWD_WELL_KNOWN_NAME,
        PKTFWD_OBJECT_NAME,
        PKTFWD_INTERFACE_NAME,
    };
    ret = loragw_ipc_setup(&dbus_config);
    if(ret < 0) {
        //MSG("loragw ipc setup failed!!!\n");
        return ret;
    }
    #if 0
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
    #endif
    return ret;
}

int pktfwd_ipc_exit()
{
    return loragw_ipc_exit();
}

#if defined(ENABLE_ADVANCED_OTA)
int pktfwd_report_update_checkout(int result, const char *msg)
{
    static int notified = 0;
    const char * state = NULL;
    const char * module = NULL;
    if(!msg )
        return LORA_IPC_ERROR_INVALID_PARAM;

    if(notified > 10) {
        return LORA_IPC_SUCCESS;
    }
    DBusMessage *message = dbus_message_new_signal(PKTFWD_OBJECT_NAME, PKTFWD_INTERFACE_NAME,
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
    module = "pktfwd";
    dbus_message_append_args(message, DBUS_TYPE_STRING, &state, DBUS_TYPE_STRING,
                             &module, DBUS_TYPE_STRING,
                             &msg, DBUS_TYPE_INVALID);

    if (FALSE == loragw_ipc_send((void *)message, NULL)) {
        dbus_message_unref(message);
        return LORA_IPC_ERROR_IO;
    }
    dbus_message_unref(message);
    notified ++;
    return LORA_IPC_SUCCESS;
}
#endif

#if defined(ENABLE_MONITOR)
int pktfwd_notify_monitor_alarms(int type, const char *pmsg)
{
    mon_alarm_type_t msg_type = (mon_alarm_type_t)type;
    if(msg_type > MON_ALARM_REBOOT || !pmsg) {

        return LORA_IPC_ERROR_INVALID_PARAM;
    }
    DBusMessage *message = dbus_message_new_signal(PKTFWD_OBJECT_NAME, PKTFWD_INTERFACE_NAME,
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