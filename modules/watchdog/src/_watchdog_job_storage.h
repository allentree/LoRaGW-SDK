/*
 * _watchdog_job_storage.h
 *
 *  Created on: 2017年11月14日
 *      Author: Zhongyang
 */

#ifndef MODULES_WATCHDOG__WATCHDOG_JOB_STORAGE_H_
#define MODULES_WATCHDOG__WATCHDOG_JOB_STORAGE_H_

#include "_watchdog_includes.h"

int watchdog_dump_process_list(WatchdogProcess *process_list);
int watchdog_load_process_list(WatchdogProcess *process_list);

#endif /* MODULES_WATCHDOG__WATCHDOG_JOB_STORAGE_H_ */
