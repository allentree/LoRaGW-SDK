/*
 * _watchdog_job_mgmt.h
 *
 *  Created on: 2017年11月10日
 *      Author: Zhongyang
 */

#ifndef MODULES_WATCHDOG__WATCHDOG_JOB_MGMT_H_
#define MODULES_WATCHDOG__WATCHDOG_JOB_MGMT_H_

#include "_watchdog_includes.h"

extern pthread_mutex_t g_mutex_watchdog_job_queue;

void *watchdog_worker_restart_job(void *job);
void *watchdog_worker_parse_job_feeddog(void *job);

int watchdog_process_check_timeout_kill();
DBusHandlerResult watchdog_filter_signal_feeddog_handler(DBusConnection *connection, DBusMessage *msg, void *user_data);

#endif /* MODULES_WATCHDOG__WATCHDOG_JOB_MGMT_H_ */
