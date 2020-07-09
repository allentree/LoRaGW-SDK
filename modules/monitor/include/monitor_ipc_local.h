#ifndef _MONITOR_IPC_LOCAL_H_
#define _MONITOR_IPC_LOCAL_H_

#include "loragw_interface_common.h"



int monitor_dbus_setup();
int monitor_dbus_exit();

int monitor_gwmp_msg_send(const char * pmsg);
int monitor_send_alarm_interal(int type, const char *pmsg);
#ifdef ENABLE_ADVANCED_OTA
int monitor_notify_update_checkout_result(int result, const char *msg);
#endif
#endif
