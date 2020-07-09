#include "_watchdog_includes.h"

uint32_t watchdog_job_crc32_calculate(WatchdogJob *job)
{
    uint32_t crc32 = WATCHDOG_CRC32_SEED;
    if (job) {
        crc32 = _watchdog_crc32_ptr((ptrdiff_t)(job->BusUniqueName), crc32);
        crc32 = _watchdog_crc32_ptr((ptrdiff_t)(job->UUID), crc32);
        crc32 = _watchdog_crc32_ptr((ptrdiff_t)(job->ServiceWellKnownName), crc32);
        crc32 = _watchdog_crc32_u32((uint32_t)(job->CountDown), crc32);
    }
    return crc32;
}

int watchdog_job_crc32_valid(WatchdogJob *job)
{
    if (NULL == job) {
        return 0;
    }

    return watchdog_job_crc32_calculate(job) == job->CRC32;
}

void watchdog_job_init(WatchdogJob *job)
{
    if (job) {
        memset(job, 0, sizeof(WatchdogJob));
        job->CRC32 = watchdog_job_crc32_calculate(job);
    }
}

WatchdogThread *watchdog_thread_create()
{
    WatchdogThread *thread = (WatchdogThread *) malloc(sizeof(WatchdogThread));
    if (NULL == thread) {
        return NULL;
    }

    memset(thread, 0, sizeof(WatchdogThread));
    INIT_LIST_HEAD(&thread->list_node);
    return thread;
}

WatchdogProcess *watchdog_process_create()
{
    WatchdogProcess *_new_process = (WatchdogProcess *) malloc(sizeof(WatchdogProcess));
    if (NULL == _new_process) {
        return NULL;
    }

    memset(_new_process, 0, sizeof(WatchdogProcess));
    _new_process->PID = ~0u;
    INIT_LIST_HEAD(&_new_process->list_node);
    INIT_LIST_HEAD(&_new_process->ThreadListHead.list_node);
    return _new_process;
}

void watchdog_job_free(WatchdogJob *job)
{
    if (job) {
        if ((job)->BusUniqueName) {
            free((job)->BusUniqueName);
        }
        if ((job)->UUID) {
            free((job)->UUID);
        }
        if ((job)->ServiceWellKnownName) {
            free((job)->ServiceWellKnownName);
        }
        free(job);
    }
}

void watchdog_thread_free(WatchdogThread *thread)
{
    if (thread) {
        if ((thread)->UUID) {
            free((thread)->UUID);
        }
        if ((thread)->WellKnownName) {
            free((thread)->WellKnownName);
        }
        free(thread);
    }
}

void watchdog_process_free(WatchdogProcess *process)
{
    if (process) {
        if ((process)->BusUniqueName) {
            free((process)->BusUniqueName);
        }
        if ((process)->CWD) {
            free((process)->CWD);
        }
        if ((process)->Cmdline) {
            free((process)->Cmdline);
        }
        free(process);
    }
}

struct timespec watchdog_exact_time()
{
	struct timespec monotonic_now;
	struct timeval tv;
	if (0 == clock_gettime(CLOCK_MONOTONIC, &monotonic_now)) {
		return  monotonic_now;
	}
	else
	{
		gettimeofday(&tv, NULL);
		monotonic_now.tv_sec = tv.tv_sec;
		monotonic_now.tv_nsec = tv.tv_usec * 1000;
		return monotonic_now;
	}
	 
}

time_t watchdog_time()
{
    struct timespec monotonic_now;
    if (0 == clock_gettime(CLOCK_MONOTONIC, &monotonic_now)) {
        return (time_t) monotonic_now.tv_sec;
    } else {
        return time(NULL);
    }
}
