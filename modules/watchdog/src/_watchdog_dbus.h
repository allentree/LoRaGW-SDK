/*
 * _watchdog_dbus.h
 *
 *  Created on: 2017年11月13日
 *      Author: Zhongyang
 */

#ifndef MODULES_WATCHDOG__WATCHDOG_DBUS_H_
#define MODULES_WATCHDOG__WATCHDOG_DBUS_H_

#include "_watchdog_includes.h"

// api
int watchdog_dbus_init_default();
int watchdog_dbus_init_open_connection();
int watchdog_dbus_init_request_well_known_name();

int watchdog_dbus_uninit();

int watchdog_dbus_add_filter(DBusHandleMessageFunction handler);

int watchdog_dbus_send_terminate_signal(WatchdogProcess *process, WatchdogThread *thread, int32_t countdown);
int watchdog_dbus_ping_daemon_block(char *bus_uuid);
uint32_t watchdog_dbus_request_pid_block(const char *bus_connection_name);
#ifdef WATCHDOG_RESTART_BY_DBUS
    int watchdog_dbus_start_service_by_name_block(const char *well_known_name);
#endif

// threads
void *watchdog_thread_dbus_dispatcher(void *args);
void *watchdog_thread_dbus_daemon_watcher(void *args);

// global variables
extern time_t gt_last_success_ping_dbus_daemon;
extern time_t gt_watchdog_dbus_ping_daemon_timeout_sec;
extern uint32_t gu_daemon_pid;
extern char gstr_daemon_uuid[64];

#endif /* MODULES_WATCHDOG__WATCHDOG_DBUS_H_ */
