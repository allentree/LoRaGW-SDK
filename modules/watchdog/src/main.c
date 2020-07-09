/*
 * main.c
 *
 *  Created on: 2017年11月9日
 *      Author: Zhongyang
 */

#include "_watchdog_includes.h"
#include "_watchdog_system_feed.h"
#include <sys/prctl.h>

#define SYSTEM_WATCHDOG_DEV "/dev/watchdog"

static int32_t s_pool_thread_count = 10;
static int32_t feed_system_timer_interval = 15;

int32_t g_signal_require_exit = 0;
pthread_t g_thread_dbus_daemon_watcher;

void *watchdog_thread_timer(void *args);

static int get_gateway_root(char *dir)
{
    static char abs_gateway_root[FILENAME_MAX + 1] = "../";
    static int first = 1;
    if (first == 1) {
        char rel_gateway_root[FILENAME_MAX + 1];
        int len = readlink("/proc/self/exe", rel_gateway_root, FILENAME_MAX);
        if (len <= 0) {
            return 1;
        }
        rel_gateway_root[len] = '\0';
        char *path_end = strrchr(rel_gateway_root, '/');
        if (path_end) {
            *path_end = '\0';
        }
        strcat(rel_gateway_root, "/../");
        char *real_path = realpath(rel_gateway_root, abs_gateway_root);
        if (NULL == real_path) {
            strcpy(dir, rel_gateway_root);
            return 1;
        }
        first = 0;
    }
    strcpy(dir, abs_gateway_root);

    return 0;
}


void *watchdog_thread_timer(void *args)
{
    time_t epoch_now;
	static int feed_system_count = 0;
    while (1) {
        epoch_now = watchdog_time();
        if (epoch_now - gt_last_success_ping_dbus_daemon > gt_watchdog_dbus_ping_daemon_timeout_sec) {
            struct tm tm_buffer;
            const struct tm *_tm = gmtime(&gt_last_success_ping_dbus_daemon);
            if (NULL != _tm) {
                char str_time[128];
                strftime(str_time, sizeof(str_time), "%a %Y-%m-%d %H:%M:%S %Z", _tm);
                log_err( "DBus hangs, restarting system. Last success ping time is: %s\r\n", str_time);
            } else {
                log_err( "DBus hangs, restarting system. Couldn't get last success ping time.\r\n");
            }
			system("reboot");
			#if 0
            char cwd_buffer[FILENAME_MAX + 1];
            if (0 == get_gateway_root(cwd_buffer)) {
                do {
                    if (NULL != args) {
                        char *argv0 = (char *) args;
                        char *proc_name = strrchr(argv0, '/');
                        if (NULL == proc_name) {
                            log_err( "executable file name is illegal! Trying to reboot system anyway.\n");
                            break;
                        }
                        int len = strlen(proc_name);
                        if (len <= 1) {
                            log_err( "executable file name is illegal! Trying to reboot system anyway.\n");
                            break;
                        }
                        int i;
                        for (i = 1; i < len; ++i) {
                            proc_name[i] = '_';
                        }
                    }
                } while (0);
                prctl(PR_SET_NAME, "________", 0, 0, 0);
                strcat(cwd_buffer, "/" WATCHDOG_SCRIPT_DIR "/" WATCHDOG_SCRIPT_RESTART_GATEWAY);
                log_debug( "executing: %s\n", cwd_buffer);
#ifdef ENABLE_WATCH_DBUS_DAEMON
                execlp("/bin/sh", "-c", cwd_buffer, NULL);
#else
                log_debug( "ENABLE_WATCH_DBUS_DAEMON was not defined, watchdog won't restart gateway.\n");
#endif
            } else {
                log_fatal( "Unable to restart system, executable file path not found in /proc/self !\n");
                exit(1);
            }
			#endif
        }

        watchdog_process_check_timeout_kill();
        usleep(1000000);
		
		feed_system_count ++;
		if(feed_system_count >= feed_system_timer_interval -1)
		{
			_watchdog_system_feeddog();
			feed_system_count = 0;
		}
		
        if (SIGNAL_REQUIRE_EXIT_VALID == g_signal_require_exit) {
            return NULL;
        }
    }
    return NULL;
}

void sig_int_handler(int sig)
{
    if (sig) {
        log_err( "Caught signal: %s, exiting...\r\n", strsignal(sig));
        if (SIGINT == sig) {
            if (SIGNAL_REQUIRE_EXIT_VALID == g_signal_require_exit) {
                exit(0);
            }
            g_signal_require_exit = SIGNAL_REQUIRE_EXIT_VALID;
        }
    }
}

#if 0
void create_crontab()
{
    char str_exe[FILENAME_MAX];
    size_t fn_str_len = readlink("/proc/self/exe", str_exe, FILENAME_MAX);
    if (fn_str_len < 0) {
        return;
    }
    str_exe[fn_str_len] = '\0';

    char str_crontab[FILENAME_MAX];
    snprintf(str_crontab, FILENAME_MAX, "*/1 * * * * root %s", str_exe);
    FILE *fh_crontab = fopen("/etc/crond.d/gateway_watchdog", "w");
    if (fh_crontab) {
        fputs(str_crontab, fh_crontab);
        fclose(fh_crontab);
        log_info( "crontab created at /etc/cron.d/gateway_watchdog, \r\n"
              "  crontab content: %s",
              str_crontab);
    } else {
        log_err( "unable to create /etc/cron.d/gateway_watchdog, \r\n"
              "  crontab content: %s",
              str_crontab);
    }
}
#endif

int main(int argc, const char **argv)
{
#if 0
    // make sure using root
    if (geteuid() != 0) {
        printf("Please run as root (with sudo). exiting now\r\n");
        return 1;
    }
#endif

    // 忽略子进程的结束信号
    struct sigaction sig_sigchld;
    memset(&sig_sigchld, 0, sizeof(struct sigaction));
    sigemptyset(&sig_sigchld.sa_mask);
    sig_sigchld.sa_handler = SIG_IGN;
    sigaction(SIGCHLD, &sig_sigchld, NULL);

    // 响应 SIGINT。
    struct sigaction sig_int;
    memset(&sig_int, 0, sizeof(struct sigaction));
    sigemptyset(&sig_int.sa_mask);
    sig_int.sa_handler = sig_int_handler;
    sigaction(SIGINT, &sig_int, NULL);
#if defined(ENABLE_REMOTE_LOG)
    log_init(WATCHDOG_DBUS_BUS_WELL_KNOWN_NAME, LOG_FILE, LOG_LEVEL_DEBUG, LOG_MOD_VERBOSE);
    log_file_init(WATCHDOG_DBUS_BUS_WELL_KNOWN_NAME, 10 , 2);
#endif
    /*
    setup system watchdog
    */
	if(_watchdog_system_feeddog_setup(SYSTEM_WATCHDOG_DEV, feed_system_timer_interval) < 0)
	{
		log_err( "Unable to setup system hardware watchdog: %s!\r\n", SYSTEM_WATCHDOG_DEV);
		/*we start cron deamon here when setup hardware watchdog failed!*/
		if(_watchdog_system_crond_setup() < 0)
		{
			log_err("system cron setup failed!!!\n\r");
			log_err( "there will be no guard watching watchdog!!!\n");
		}
		
		//return 1;
	}
    // init mutex
    pthread_mutex_init(&g_mutex_watchdog_job_queue, NULL);

    // init dbus
    int dbus_init_result = watchdog_dbus_init_default();
    if (dbus_init_result != WATCHDOG_ERROR_SUCEESS) {
        log_err( "Unable to open dbus connection.\r\n");
        return 1;
    }

    watchdog_dbus_add_filter(watchdog_filter_signal_feeddog_handler);
    // TODO try recover from crash
    //    if (_watchdog_was_crashed()) {
    //        _watchdog_load_stored_file();
    //    }

    // init thread pool
    tp_pool_init(s_pool_thread_count);

    // start dbus dispatcher;
    watchdog_dbus_ping_daemon_block(gstr_daemon_uuid);
#ifdef DBUS_SUPPORT_SERVER_PID
    gu_daemon_pid = watchdog_dbus_request_pid_block("org.freedesktop.DBus");
#endif
    gt_last_success_ping_dbus_daemon = watchdog_time();
    log_debug( "DBus Daemon PID is: %u\n", gu_daemon_pid);

    if (0 != pthread_create(&g_thread_dbus_daemon_watcher, NULL, watchdog_thread_dbus_daemon_watcher, NULL)) {
        log_err( "Unable to create dbus_daemon_watcher thread.\r\n");
        return 1;
    }

    // start timer.
    watchdog_thread_timer((void *) argv[0]);

    pthread_join(g_thread_dbus_daemon_watcher, NULL);
    tp_pool_destroy();
    watchdog_dbus_uninit();
	_watchdog_system_feeddog_exit();
#if defined(ENABLE_REMOTE_LOG)    
	log_destroy();
#endif	

    return 0;
}
