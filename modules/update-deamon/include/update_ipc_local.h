#ifndef _UPDATE_IPC_LOCAL_H_
#define _UPDATE_IPC_LOCAL_H_

#include "loragw_interface_common.h"


int update_dbus_setup();
int update_dbus_exit();
int update_report_ota_ver_to_server(const char * ver);
int ota_report_process_state(int state, const char * string);

int query_major_process_running_state();
#endif