/*
 * _watchdog_structs.h
 *
 *  Created on: 2017年11月10日
 *      Author: Zhongyang
 */

#ifndef MODULES_WATCHDOG__WATCHDOG_STRUCTS_H_
#define MODULES_WATCHDOG__WATCHDOG_STRUCTS_H_

#include "_watchdog_includes.h"

typedef struct WatchdogThreadTag {
    struct list_head list_node;

    char *UUID;
    char *WellKnownName;
	int opreation;
    struct timespec EpochTimeToKill;
} WatchdogThread;

typedef struct WatchdogProcessTag {
    struct list_head list_node;

    char *BusUniqueName;
    char *CWD;
    char *Cmdline;
    uint32_t PID;
    int Killing;

    WatchdogThread ThreadListHead;
} WatchdogProcess, *WatchdogProcessList;

typedef struct WatchdogJobTag {
    char *BusUniqueName;
    char *ServiceWellKnownName;
    char *UUID;
    int32_t CountDown;
	int opreation;
    uint32_t CRC32;
} WatchdogJob;

typedef struct WatchdogRestartJobTag {
    WatchdogProcess *Process;
    WatchdogThread *Thread;
} WatchdogRestartJob;

uint32_t watchdog_job_crc32_calculate(WatchdogJob *job);
int watchdog_job_crc32_valid(WatchdogJob *job);
void watchdog_job_init(WatchdogJob *job);
void watchdog_job_free(WatchdogJob *job);

WatchdogThread *watchdog_thread_create();
void watchdog_thread_free(WatchdogThread *thread);

WatchdogProcess *watchdog_process_create();
void watchdog_process_free(WatchdogProcess *process);

time_t watchdog_time();
struct timespec watchdog_exact_time();

#endif /* MODULES_WATCHDOG__WATCHDOG_STRUCTS_H_ */
