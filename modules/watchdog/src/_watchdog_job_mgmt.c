/*
 * _watchdog_list_helpers.c
 *
 *  Created on: 2017年11月10日
 *      Author: Zhongyang
 */
#include "_watchdog_includes.h"

pthread_mutex_t g_mutex_watchdog_job_queue;
WatchdogProcess g_watchdog_process_head;

int g_waiting_sec_before_kill_default = 5;
int g_waiting_sec_before_restart_default = 4;

static int _watchdog_append_new_job_block(WatchdogProcess *const process_list, const WatchdogJob *job);
static int _watchdog_process_delete_deep(WatchdogProcess *process);

static WatchdogProcess *_watchdog_get_process_list()
{
    static int first = 1;
    if (first) {
        INIT_LIST_HEAD(&g_watchdog_process_head.list_node);
        INIT_LIST_HEAD(&g_watchdog_process_head.ThreadListHead.list_node);
        first = 0;
    }
    return &g_watchdog_process_head;
}

static int _watchdog_is_job_legal(const WatchdogJob *job)
{
    if ((NULL == job) || (NULL == job->BusUniqueName) || (NULL == job->UUID)) {
        return 0;
    }
	if(job->opreation < 0)
		return 0;
    if ((-1 == job->CountDown) || (job->CountDown > 0)) {
        return 1;
    } else {
        return 0;
    }
}

static int _watchdog_thread_remove_from_process(WatchdogProcess *process, WatchdogThread *thread)
{
    if (thread && process && (thread != &process->ThreadListHead)) {
        list_del(&thread->list_node);
        watchdog_thread_free(thread);
    }
    return 0;
}

static int _watchdog_process_delete_deep(WatchdogProcess *process)
{
    if (NULL == process) {
        return WATCHDOG_ERROR_INVALID_PARAM;
    }

    log_warn( "Deleting Process: %s\r\n", process->BusUniqueName);
    WatchdogThread *thread_node;
    WatchdogThread *psafe;
    list_for_each_entry_safe(thread_node, psafe, &process->ThreadListHead.list_node, list_node) {
        log_warn( "Deleting Thread: %s, [%016x]\r\n", thread_node->WellKnownName, thread_node);
        list_del(&thread_node->list_node);
        watchdog_thread_free(thread_node);
    }

    assert(list_empty(&process->ThreadListHead.list_node));
    list_del(&process->list_node);
    watchdog_process_free(process);
    return WATCHDOG_ERROR_SUCEESS;
}

static int _watchdog_job_exists(const WatchdogProcess *process_list,
                                const WatchdogJob *job,
                                WatchdogProcess **found_process,
                                WatchdogThread **found_thread)
{
    if (!_watchdog_is_job_legal(job)) {
        return 0;
    }
    WatchdogProcess *process_head = _watchdog_get_process_list();
    if (NULL == process_head) {
        return 0;
    }

    WatchdogProcess *process_node = NULL;
    list_for_each_entry(process_node, &process_head->list_node, list_node) {
        WatchdogThread *thread_node;
        if (0 == strcmp(process_node->BusUniqueName, job->BusUniqueName)) {
            if (found_process) {
                *found_process = process_node;
            }
            list_for_each_entry(thread_node, &process_node->ThreadListHead.list_node, list_node) {
                if (0 == strcmp(thread_node->UUID, job->UUID)
                    && (0 == strcmp(thread_node->WellKnownName, job->ServiceWellKnownName))) {
                    if (found_thread) {
                        *found_thread = thread_node;
                    }
                    return 1;
                }
            }
        }
    }

    return 0;
}

static int _watchdog_append_new_job_block(WatchdogProcess *const process_list, const WatchdogJob *job)
{
    if ((NULL == process_list) || (NULL == job)) {
        return WATCHDOG_ERROR_INVALID_PARAM;
    }

    // 假定 job 一定不在队列中。
    // assert(!_watchdog_job_exists(process_list, job));

    WatchdogProcess *_new_process = watchdog_process_create();
    if (NULL == _new_process) {
        return WATCHDOG_ERROR_NO_MEM;
    }

#if defined WATCHDOG_RESTART_BY_PID

    // configure PID, CWD, Cmdline
    _new_process->PID = watchdog_dbus_request_pid_block(job->BusUniqueName);
    if (_new_process->PID == ~(0ul)) {
        return WATCHDOG_ERROR_INVALID_PARAM;
    }

    char fn_cmdline[FILENAME_MAX];
    snprintf(fn_cmdline, FILENAME_MAX, "/proc/%u/cmdline", _new_process->PID);
    FILE *fh_cmdline = fopen(fn_cmdline, "r");
    if (NULL == fh_cmdline) {
        if (_new_process != process_list) {
            free(_new_process);
        }
        return WATCHDOG_ERROR_IO;
    }

    if ((fscanf(fh_cmdline, "%s", fn_cmdline) <= 0) || (strlen(fn_cmdline) <= 0)) {
        fclose(fh_cmdline);
        if (_new_process != process_list) {
            free(_new_process);
        }
        return WATCHDOG_ERROR_IO;
    }
    fclose(fh_cmdline);
    fh_cmdline = NULL;
    _new_process->Cmdline = strdup(fn_cmdline);

    char cwd_buff[FILENAME_MAX], fn_cwd[FILENAME_MAX];
    snprintf(fn_cwd, FILENAME_MAX, "/proc/%u/cwd", _new_process->PID);
    size_t cwd_strlen = readlink(fn_cwd, cwd_buff, FILENAME_MAX);
    cwd_buff[cwd_strlen] = '\0';
    _new_process->CWD = strdup(cwd_buff);

#elif defined WATCHDOG_RESTART_BY_DBUS
#endif

    _new_process->BusUniqueName = strdup(job->BusUniqueName);
    //    _new_process->PID = watchdog_dbus_request_pid_block(job->BusUniqueName);
    WatchdogThread *thread = watchdog_thread_create();
    if (thread) {
        thread->WellKnownName = strdup(job->ServiceWellKnownName);
        thread->UUID = strdup(job->UUID);
		thread->EpochTimeToKill = watchdog_exact_time();
        thread->EpochTimeToKill.tv_sec += job->CountDown;
		thread->opreation = job->opreation;
    }

    list_add_tail(&thread->list_node, &_new_process->ThreadListHead.list_node);
    list_add_tail(&_new_process->list_node, &process_list->list_node);
    return WATCHDOG_ERROR_SUCEESS;
}

void *watchdog_worker_parse_job_feeddog(void *job_void)
{
    if (NULL == job_void) {
        return NULL;
    }
    WatchdogJob *job = job_void;
	/*remove crc*/
	/*
    if (!watchdog_job_crc32_valid(job)) {
        return NULL;
    }
    */
    if (!_watchdog_is_job_legal(job)) {
        watchdog_job_free(job);
        job = NULL;
        return NULL;
    }

    WatchdogProcess *process = NULL;
    WatchdogThread *thread = NULL;

    pthread_mutex_lock(&g_mutex_watchdog_job_queue);
    WatchdogProcess *process_head = _watchdog_get_process_list();
    if (_watchdog_job_exists(process_head, job, &process, &thread)) {
        if (process->Killing) {
            log_info( "Process(%s) is being killed, will not accept new feedDog request.\n", job->BusUniqueName);
        } else {
            if (job->CountDown == -1) {
                _watchdog_thread_remove_from_process(process, thread);
                if (list_empty(&(process->ThreadListHead.list_node))) {
                    list_del(&process->list_node);
                    watchdog_process_free(process);
                }
            } else if (job->CountDown > 0) {
                thread->EpochTimeToKill = watchdog_exact_time();
				thread->EpochTimeToKill.tv_sec += job->CountDown;
				thread->opreation = job->opreation;
            }
        }
    } else {
        if (job->CountDown <= 0) {
            log_err( "Received a new job but its Countdown <= 0.\r\n");
        } else {
            if (process) {
                if (process->Killing) {
                    log_info( "Process(%s) is being killed, will not accept new feedDog request.\n", job->BusUniqueName);
                } else {
                    log_info( "Appending new thread(%s) to existing process(%s).\r\n", job->ServiceWellKnownName,
                          job->BusUniqueName);
                    WatchdogThread *_new_thread = watchdog_thread_create();
                    if (_new_thread) {
                        _new_thread->UUID = strdup(job->UUID);
                        _new_thread->WellKnownName = strdup(job->ServiceWellKnownName);
                        _new_thread->EpochTimeToKill = watchdog_exact_time();
						_new_thread->EpochTimeToKill.tv_sec	+= job->CountDown;
						_new_thread->opreation = job->opreation;
                        list_add_tail(&_new_thread->list_node, &process->ThreadListHead.list_node);
                    }
                }
            } else {
                if (0 != _watchdog_append_new_job_block(process_head, job)) {
                    log_err( "Failed to append a new job to queue.\r\n");
                }
            }
        }
    }
    pthread_mutex_unlock(&g_mutex_watchdog_job_queue);

    watchdog_job_free(job);
    job = NULL;
    return NULL;
}

void *watchdog_worker_restart_job(void *args)
{
    WatchdogRestartJob *job = (WatchdogRestartJob *) args;
    if (NULL == job) {
        return NULL;
    }
    WatchdogProcess *process = job->Process;
    WatchdogThread *thread = job->Thread;
    if ((NULL == process) || (NULL == thread)) {
        free(job);
        return NULL;
    }
	/*
	feeddog timeout opreation is reboot system!
	*/
	if(thread->opreation == 0)
	{
		log_err( "system reboot because of timeout opreation caused by process %s's thread id %s!\n\r",\
								thread->WellKnownName, thread->UUID);
		system("reboot");
		return NULL;
	}
	
    uint32_t pid = watchdog_dbus_request_pid_block(process->BusUniqueName);
    pid_t ipid = *(pid_t *) &pid;
#if defined WATCHDOG_RESTART_BY_PID
    if (pid != process->PID) {
        _watchdog_process_delete_deep(process);
        return NULL;
    }
#endif
    if ((pid != ~0u) && (ipid > 0)) {
        log_warn( "Sending terminate signal to PID: %u\r\n", pid);
        watchdog_dbus_send_terminate_signal(process, thread, g_waiting_sec_before_kill_default);
        if (0 != kill(pid, SIGTERM)) {
            if (ESRCH == errno) {
                log_warn( "PID: %i doesn't exist, restarting: %s\r\n", ipid, thread->WellKnownName);
            } else if (EPERM == errno) {
                log_err( "Watchdog wasn't run as root, can not kill module: %s\r\n", thread->WellKnownName);
            } else {
                log_err( "Unknown error: %i\r\n", errno);
            }
        } else {
            // 正常发送了 SIGTERM，认为之后不会出现 PID 不存在或者权限不足的问题。
            time_t epoch_now = watchdog_time();
            while (watchdog_time() - epoch_now <= g_waiting_sec_before_kill_default) {
                usleep(1000000);
            }

            log_warn( "Sending KILL signal to PID: %u\r\n", pid);
            kill(pid, SIGKILL);

            epoch_now = watchdog_time();
            uint32_t pid_after = ~0u;

            do {
                pid_after = watchdog_dbus_request_pid_block(thread->WellKnownName);
                if ((~0u) == pid_after) {
                    break;
                }
                usleep(1000000);
            } while (watchdog_time() - epoch_now <= g_waiting_sec_before_restart_default);

            if ((~0u) != pid_after) {
                log_err( "Unable to kill %s(%s) with PID: %u\r\n", thread->WellKnownName, process->BusUniqueName, pid);
            }
        }
    }


#if defined WATCHDOG_RESTART_BY_DBUS
    log_warn( "Starting service by name: %s\r\n", thread->WellKnownName);
    watchdog_dbus_start_service_by_name_block(thread->WellKnownName);
#elif defined WATCHDOG_RESTART_BY_PID
#error Not implemented yet!
#endif

    uint32_t pid_after = ~0u;
    pid_after = watchdog_dbus_request_pid_block(thread->WellKnownName);
    if (((~0u) != pid_after) && (pid_after != pid)) {
        log_info( "%s started service successfully, with new PID:%d \r\n", thread->WellKnownName, (pid_t) pid_after);
    }

    free(job);

    pthread_mutex_lock(&g_mutex_watchdog_job_queue);
    _watchdog_process_delete_deep(process);
    pthread_mutex_unlock(&g_mutex_watchdog_job_queue);

    return NULL;
}

// TODO 按照预先时间排序可以提高性能。如果并发性能不够的话可以考虑在这里提升性能。
int watchdog_process_check_timeout_kill()
{
    int process_terminated = 0;
    struct timespec epoch_now = watchdog_exact_time();

    pthread_mutex_lock(&g_mutex_watchdog_job_queue);

    WatchdogProcess *process_head = _watchdog_get_process_list();
    WatchdogProcess *process = process_head;
    WatchdogProcess *process_guard;

    if (process_head) {
        list_for_each_entry_safe(process, process_guard, &process_head->list_node, list_node) {
            if (process->Killing) {
                continue;
            }
            //            log_debug( "\nExaming: Process BusUniqueName: %s\n", process->BusUniqueName);
            if (FALSE == list_empty(&process->ThreadListHead.list_node)) {
                WatchdogThread *thread;
                list_for_each_entry(thread, &process->ThreadListHead.list_node, list_node) {
                    //                    log_debug( "\n  Thread WKN: %s, unique name: %s\n", thread->WellKnownName, thread->UUID);
                    if (((epoch_now.tv_sec > thread->EpochTimeToKill.tv_sec) \
							|| ((epoch_now.tv_sec == thread->EpochTimeToKill.tv_sec) && (epoch_now.tv_nsec > thread->EpochTimeToKill.tv_nsec) ) )\
									&& (0 == process->Killing)) {
                        WatchdogRestartJob *job = (WatchdogRestartJob *) malloc(sizeof(WatchdogRestartJob));
                        if (job) {
                            process->Killing = 1;
                            log_warn( "Time up, killing %s, thread name: %s\r\n", thread->WellKnownName, thread->UUID);
                            job->Process = process;
                            job->Thread = thread;
                            tp_pool_add_worker(watchdog_worker_restart_job, job);
                            ++process_terminated;
                        }
                    }
                }
            } else {
                list_del(&process->list_node);
                watchdog_process_free(process);
            }
        }
    }

    pthread_mutex_unlock(&g_mutex_watchdog_job_queue);
    return process_terminated;
}

DBusHandlerResult watchdog_filter_signal_feeddog_handler(DBusConnection *connection, DBusMessage *msg, void *user_data)
{
    //   DBUS_HANDLER_RESULT_HANDLED,         /**< Message has had its effect - no need to run more handlers. */
    //   DBUS_HANDLER_RESULT_NOT_YET_HANDLED, /**< Message has not had any effect - see if other handlers want it. */
    if ((NULL == msg)) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    int msg_type = dbus_message_get_type(msg);
    const char *msg_interface = dbus_message_get_interface(msg);
    const char *msg_member = dbus_message_get_member(msg);

    if (DBUS_MESSAGE_TYPE_SIGNAL != msg_type) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    if (FALSE == dbus_message_is_signal(msg, WATCHDOG_DBUS_INTERFACE, WATCHDOG_DBUS_SIGNAL_IN_FEEDDOG)) {
        log_info(
              "Message unwanted: %s.%s, expecting:" WATCHDOG_DBUS_INTERFACE "." WATCHDOG_DBUS_SIGNAL_IN_FEEDDOG "\r\n",
              msg_interface ? msg_interface : "NULL",
              msg_member ? msg_member : "NULL");

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    /*
     * http://gitlab.alibaba-inc.com/iot-gateway/gateway/wikis/keep_alive_api
     * Signal body:
     * - wkn(string):       well known name
     * - uuid(string):      线程的唯一标识符，保活模块用来记录线程的 countdown
     * - countdown(int):    倒计时时间，传入 -1 停止守护。
     *                      计划使用“秒”作为单位，毫秒级的精度对调度压力很大。
     *                      （毫秒级的精度可能可以通过 Linux kernel module 来减轻系统负荷，
     *                     但是对 Linux 的依赖就更强了，移植和兼容性可能有风险（待评估）。
     */
    DBusError dbus_error;
    char *str_uuid = NULL;
    char *str_wkn = NULL;
    int countdown = 0;
	int opreation = -1;

    // TODO load args one by one to support variable argument number.
    dbus_error_init(&dbus_error);
    dbus_message_get_args(msg, &dbus_error,
                          DBUS_TYPE_STRING,
                          &str_wkn,
                          DBUS_TYPE_STRING,
                          &str_uuid,
                          DBUS_TYPE_INT32,
                          &countdown,
                          DBUS_TYPE_INT32,
                          &opreation,
                          DBUS_TYPE_INVALID);

    if (dbus_error_is_set(&dbus_error)) {
        log_err( "Unable to get signal args:\r\n%s:\r\n%s\r\n", dbus_error.name, dbus_error.message);
        dbus_error_free(&dbus_error);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    WatchdogJob *job = (WatchdogJob *) malloc(sizeof(WatchdogJob));
    if (NULL == job) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    watchdog_job_init(job);
    job->BusUniqueName = strdup(dbus_message_get_sender(msg));
    job->UUID = strdup(str_uuid);
    job->ServiceWellKnownName = strdup(str_wkn);
    job->CountDown = countdown;
	job->opreation = opreation;
	/*remove crc */
    //job->CRC32 = watchdog_job_crc32_calculate(job);

    #if 0
    log_info( "\r\n"
          "  Appending job to process queue,\r\n"
          "  Bus unique name: %s\r\n"
          "  uuid:            %s\r\n"
          "  Service WKN:     %s\r\n"
          "  count down:      %d seconds\r\n"
          "  timeout opreation:      %d\r\n",
          job->BusUniqueName, job->UUID, job->ServiceWellKnownName, job->CountDown, job->opreation);
    #endif

    tp_pool_add_worker(watchdog_worker_parse_job_feeddog, job);
    return DBUS_HANDLER_RESULT_HANDLED;
}

