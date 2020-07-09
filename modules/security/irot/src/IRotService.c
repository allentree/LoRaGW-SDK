#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <dbus/dbus.h>
#include <signal.h>
#include "tfs_log.h"

#include "irot_private.h"
#include "IRotKm.h"

#if defined(ENABLE_WATCHDOG)
#include "watch_dog_export.h"
#endif

#define DBUS_READ_WRITE_TIMEOUT_MS      (1000)
#define FEED_WATCHDOG_INTERVAL_S        (2)
#define COUNT_DOWN_INTERVAL_S           (5)
#define SIGNAL_REQUIRE_EXIT_VALID       (0x5aa5)

#define SEC_INTROSPECT_INTERFACE_NAME "org.freedesktop.DBus.Introspectable"

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

static DBusHandlerResult message_handler(DBusConnection *connection,
        DBusMessage *message, void *user_data)
{
    int message_type = dbus_message_get_type(message);

    switch (message_type) {
        case DBUS_MESSAGE_TYPE_METHOD_CALL:
            if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_GEN_KEY)) {
                irot_generate_key(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_IM_KEY)) {
                irot_import_key(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
#if 0
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_EX_KEY)) {
                irot_export_key(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
#endif
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_SIGN)) {
                irot_sign(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_VERIFY)) {
                irot_verify(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_ASYM_ENCRYPT)) {
                irot_asym_encrypt(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_ASYM_DECRYPT)) {
                irot_asym_decrypt(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_ENVE_BEGIN)) {
                irot_envelope_begin(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_ENVE_UPDATE)) {
                irot_envelope_update(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_ENVE_FINISH)) {
                irot_envelope_finish(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_INIT)) {
                irot_init(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_DEL_KEY)) {
                irot_delete_key(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
#if 0
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_DEL_ALL)) {
                irot_delete_all(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
#endif
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_MAC)) {
                irot_mac(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_CIPHER)) {
                irot_cipher(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_CLEANUP)) {
                irot_cleanup(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_GET_ID2)) {
                irot_get_id2(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_SET_ID2)) {
                irot_set_id2(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else if (dbus_message_is_method_call(message, SEC_IROT_INTERFACE_NAME, KM_GET_ATTEST)) {
                irot_get_attestation(connection, message);
                return DBUS_HANDLER_RESULT_HANDLED;
            } else {
                log_e(TAG, "not support method %s\n", dbus_message_get_member(message));
            }
            break;
        default:
            break;
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int irot_service_init(DBusConnection *connection)
{
    DBusObjectPathVTable vtable;
    DBusError error;

    vtable.message_function = message_handler;
    vtable.unregister_function = NULL;

    dbus_error_init(&error);
    dbus_connection_try_register_object_path(connection,
            SEC_IROT_OBJECT_PATH,
            &vtable,
            NULL,
            &error);
    if (dbus_error_is_set(&error)) {
        log_e(TAG, "dbus_connection_try_register_object_path dbus error (%s)\n", error.message);
        dbus_error_free(&error);
        return -1;
    }

    return 0;
}

int main(void)
{
    DBusConnection *connection;
    DBusError error;
    dbus_bool_t dbus_ret;
    int ret = 0;
    struct sigaction sig_act;

#if defined (ENABLE_REMOTE_LOG)
    log_init(SEC_IROT_WELL_KNOWN_NAME, LOG_FILE_DB, LOG_LEVEL_DEBUG, LOG_MOD_VERBOSE);
    log_file_init(SEC_IROT_WELL_KNOWN_NAME, 3 , 1);
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

    if (irot_service_init(connection)) {
        log_e(TAG, "irot service init failed\n");
        ret = -1;
        goto clean;
    }

    dbus_ret = dbus_bus_name_has_owner(connection, SEC_IROT_WELL_KNOWN_NAME, &error);
    dbus_error_parse(error);
    if(TRUE == dbus_ret) {
        log_e(TAG, "dbus_bus_name_has_owner true\n");
        ret = -1;
        goto clean;
    }

    ret = dbus_bus_request_name(connection, SEC_IROT_WELL_KNOWN_NAME, 0, &error);
    dbus_error_parse(error);
    if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret) {
        log_e(TAG, "dbus_bus_request_name fail\n");
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
        if (thread_feeddog_periodically("IROT", "main", 60, 120, &watchdog_time_keeper) < 0) {
			log_e(TAG,"OTA thread feeddog failed\n");
		}
#endif 
    }


clean:
#if defined (ENABLE_REMOTE_LOG)
    log_destroy();
#endif

    return ret;
}

