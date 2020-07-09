#ifndef _PKTFWD_IPC_LOCAL_H_
#define _PKTFWD_IPC_LOCAL_H_

#include <stdint.h>     /* C99 types */
#ifdef ENABLE_DBUS_IPC
int pktfwd_ipc_setup();
int pktfwd_ipc_exit();

#ifdef ENABLE_ADVANCED_OTA
int pktfwd_report_update_checkout(int result, const char *msg);
#endif

#ifdef ENABLE_MONITOR
int pktfwd_notify_monitor_alarms(int type, const char *msg);
#endif

#endif

#endif