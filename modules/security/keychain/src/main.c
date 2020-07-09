#include <dbus/dbus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include "tfs_log.h"
#include "irot.h"
#include "kc_private.h"
#include "kcManage.h"

#if defined(ENABLE_WATCHDOG)
#include "watch_dog_export.h"
#endif


#define DBUS_READ_WRITE_TIMEOUT_MS      (1000)
#define FEED_WATCHDOG_INTERVAL_S        (2)
#define COUNT_DOWN_INTERVAL_S           (5)
#define SIGNAL_REQUIRE_EXIT_VALID       (0x5aa5)

int g_signal_require_exit = 0;
void sig_handler(int sig)
{
    if (sig) {
        log_d(TAG, "Caught signal: %s, exiting...\r\n", strsignal(sig));
        if (SIGINT == sig || SIGTERM == sig) {
            g_signal_require_exit = SIGNAL_REQUIRE_EXIT_VALID;
        }
    }
}

int main(void)
{
    DBusConnection *connection;
    DBusError error;
    dbus_bool_t dbus_ret;
    int ret = -1;
    struct sigaction sig_act;

#if defined (ENABLE_REMOTE_LOG)
    log_init(SEC_WELL_KNOWN_NAME, LOG_FILE_DB, LOG_LEVEL_DEBUG, LOG_MOD_VERBOSE);
    log_file_init(SEC_WELL_KNOWN_NAME, 3 , 1);
#endif
    memset(&sig_act, 0, sizeof(struct sigaction));
    sigemptyset(&sig_act.sa_mask);
    sig_act.sa_handler = sig_handler;
    sigaction(SIGINT, &sig_act, NULL);
    sigaction(SIGTERM, &sig_act, NULL);

    dbus_error_init(&error);

    connection = dbus_connection_open(bus_address, &error);
    dbus_error_parse(error);
    if(NULL == connection) {
        log_e(TAG, "dbus_connection_open fail\n");
        ret = -1;
        goto clean;
    }

    dbus_ret = dbus_bus_register(connection, &error);
    dbus_error_parse(error);
    if (TRUE != dbus_ret) {
        log_e(TAG, "dbus_bus_register fail\n");
        ret = -1;
        goto clean;
    }

    ret = sec_sst_init(connection);
    if (0 != ret) {
        log_e(TAG, "sec_sst_init fail, code [%x]\n", ret);
        ret = -1;
        goto clean;
    }

    dbus_ret = dbus_bus_name_has_owner(connection, SEC_WELL_KNOWN_NAME, &error);
    dbus_error_parse(error);
    if(TRUE == dbus_ret) {
        log_e(TAG, "dbus_bus_name_has_owner true\n");
        ret = -1;
        goto clean;
    }

    ret = dbus_bus_request_name(connection, SEC_WELL_KNOWN_NAME, 0, &error);
    dbus_error_parse(error);
    if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret) {
        log_e(TAG, "dbus_bus_request_name fail\n");
        ret = -1;
        goto clean;
    }

    if (irot_init()) {
        log_e(TAG, "irot init failed\n");
        ret = -1;
        goto clean;
    }
#if defined(ENABLE_WATCHDOG)
	struct timespec watchdog_time_keeper;
	clock_gettime(CLOCK_MONOTONIC, &watchdog_time_keeper);
#endif
    while (dbus_connection_get_is_connected(connection)) {
        dbus_connection_read_write_dispatch(connection, DBUS_READ_WRITE_TIMEOUT_MS);
#if defined(ENABLE_WATCHDOG)
        if (thread_feeddog_periodically("KEYCHAIN", "main", 60, 120, &watchdog_time_keeper) < 0) {
			log_e(TAG,"OTA thread feeddog failed\n");
		}
#endif 
    }

    irot_destroy();

clean:
#if defined (ENABLE_REMOTE_LOG)
    log_destroy();
#endif

    return ret;
}
