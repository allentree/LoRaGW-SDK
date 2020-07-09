#ifndef _MQTT_IPC_LOCAL_H_
#define _MQTT_IPC_LOCAL_H_


#ifdef ENABLE_DBUS_IPC
#include "loragw_interface_common.h"
int mqtt_dbus_setup();
int mqtt_dbus_exit();
#endif

#if defined(ENABLE_ADVANCED_OTA)
int ota_notify_update_file_info(const char *version, const char * md5sum, unsigned int size, char *file_path);
int ota_notify_update_download_result(int result, int filesize);
int mqtt_notify_update_checkout_result(int result, const char *msg);
#endif

#if defined(ENABLE_MONITOR)
int mqtt_notify_monitor_gwmp_downlink_msg(const char * pmsg);
int mqtt_send_monitor_alarm(int alarm_type, const char *msg);
#endif

#endif
