#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//#include "log.h"
#include "watch_dog_export.h"
//#include "loragw_interface_configs.h"
//#include "watchdog_dbus_api.h"
#include <dbus/dbus.h>

#include "watchdog_dbus_config.h"

#define LORAGW_DBUS_NAME_PREFIX "iot.gateway.watchdog"
#define LORAGW_DBUS_OBJPATH_PREFIX "/iot/gateway/watchdog"

#define BUS_FILE_MAX_NAME 1024
typedef struct{
	char  bus_wkn[BUS_FILE_MAX_NAME];
	char  interface_name[BUS_FILE_MAX_NAME];
	char  bus_obj_path[BUS_FILE_MAX_NAME];
}watchdog_process_config_st;


watchdog_process_config_st bus_config;

#ifndef bus_address
#define bus_address "unix:path=/tmp/var/run/mbusd/mbusd_socket"
#endif

typedef struct{
	int dbus_inited ;
	DBusConnection *gp_dbus_connection;
	//int processID;
	char process_symbol[BUS_FILE_MAX_NAME];
	watchdog_terminate_callback ternimate_call;
	void * callback_args;
	int dbus_exit;
	pthread_t g_thread_dbus_recv;
}process_dbus_connecttion_st;

pthread_mutex_t dbus_lock = PTHREAD_MUTEX_INITIALIZER;


process_dbus_connecttion_st g_dbus_con = {
	0,
	0,
	-1,
	NULL,
	NULL,
	0,
	};

static DBusMessage *watchdog_new_feeddog_signal(const char *well_known_name, const char *obj_path,
        					const char *thread_unique_name, int countdown_seconds, int opr);
static int watchdog_cancel_feeddog(DBusConnection *conn, const char *well_known_name, const char *obj_path,
                            const char *thread_unique_name);
static int watchdog_send_feeddog_signal(DBusConnection *conn,
                                 const char *well_known_name,
                                 const char *obj_path, const char *thread_unique_name, int feed_interval,
                              	 int opreation);
                              	 

static int process_init_feedfog_dbus();
static void *module_dbus_msg_recving_loop(void *args);
static int process_uninit_feedfog_dbus();


int get_realpath_by_exec_dir(char* real_dir, const char* offset_to_exec)
{
    char abs_gateway_root[FILENAME_MAX + 1] = "../";

    if (NULL == real_dir)
        return -1;

   
    char rel_gateway_root[FILENAME_MAX + 1];
    int len = readlink("/proc/self/exe", rel_gateway_root, FILENAME_MAX);
    if (len <= 0)
        return -1;
    rel_gateway_root[len] = '\0';
	
    char* path_end = strrchr(rel_gateway_root, '/');
	if(NULL == path_end)
		return -1;
	
	path_end++;
    *path_end = '\0';
	/*
    strcat(rel_gateway_root, "/../");
    */
    if(!offset_to_exec || strlen(offset_to_exec) == 0)
    {
	    strcpy(real_dir, rel_gateway_root);
	    return 0;
    }
    else
    {
		strcat(rel_gateway_root, offset_to_exec);
    }
    char* real_path = realpath(rel_gateway_root, abs_gateway_root);
    if (NULL == real_path) {
        strcpy(real_dir, rel_gateway_root);
        return -1;
    }
  
    strcpy(real_dir, abs_gateway_root);

    return 0;
}


DBusMessage *watchdog_new_feeddog_signal(const char *well_known_name, const char *obj_path,
        const char *thread_unique_name, int countdown_seconds, int opr)
{
    DBusMessage *signal_feeddog = dbus_message_new_signal(obj_path, WATCHDOG_DBUS_INTERFACE,
                                  WATCHDOG_DBUS_SIGNAL_IN_FEEDDOG);

    dbus_message_set_destination(signal_feeddog, WATCHDOG_DBUS_BUS_WELL_KNOWN_NAME);

    dbus_message_append_args(signal_feeddog, DBUS_TYPE_STRING, &well_known_name, DBUS_TYPE_STRING,
                             &thread_unique_name, DBUS_TYPE_INT32, &countdown_seconds, \
                             DBUS_TYPE_INT32, &opr, DBUS_TYPE_INVALID);

    return signal_feeddog;
}

int watchdog_send_feeddog_signal(DBusConnection *conn,
                                 const char *well_known_name,
                                 const char *obj_path, const char *thread_unique_name, int feed_interval,
                              	 int opreation)
{
    if ((NULL == conn) || (NULL == well_known_name) || (NULL == obj_path) || (NULL == thread_unique_name)
        || (0 == feed_interval) ) {
        return WATCHDOG_ERROR_INVALID_PARAM;
    }

    DBusMessage *msg = watchdog_new_feeddog_signal(well_known_name, obj_path, thread_unique_name, feed_interval, opreation);
    if (FALSE == dbus_connection_send(conn, msg, NULL)) {
        dbus_message_unref(msg);
        return WATCHDOG_ERROR_IO;
    }
    dbus_message_unref(msg);

    return WATCHDOG_SUCCESS;
}
								 
int watchdog_cancel_feeddog(DBusConnection *conn, const char *well_known_name, const char *obj_path,
                            const char *thread_unique_name)
{
    void *wrap = NULL;
    return watchdog_send_feeddog_signal(conn, well_known_name, obj_path, thread_unique_name, -1, 0);
}


void *module_dbus_msg_recving_loop(void *args)
{
	DBusError error;
	char listen_str[256];
	DBusMessage *message = NULL;
	if(!g_dbus_con.gp_dbus_connection)
	{
		return NULL;
	}
	sprintf(listen_str, "type='signal',interface='%s',member='%s'",\
							WATCHDOG_DBUS_INTERFACE,WATCHDOG_DBUS_SIGNAL_OUT_TERMINATE);
	dbus_error_init(&error);
	dbus_bus_add_match(g_dbus_con.gp_dbus_connection, listen_str ,&error);
	if (dbus_error_is_set(&error)) 
	{
		dbus_error_free(&error);
		return NULL;
	}
	while(!g_dbus_con.dbus_exit)
	{
		//block while recving the signal
		if(dbus_connection_read_write(g_dbus_con.gp_dbus_connection, 500))
		{
	        message = dbus_connection_pop_message(g_dbus_con.gp_dbus_connection);
	        if (message == NULL) {
	            continue;
	        }
			if (FALSE == dbus_message_is_signal(message, \
							WATCHDOG_DBUS_INTERFACE, WATCHDOG_DBUS_SIGNAL_OUT_TERMINATE)) 
			{
				continue;
			}
			char *str_uuid = NULL;
    		char *str_wkn = NULL;
			int countdown = 0; 
			//int opreation = -1;
			dbus_message_get_args(message, &error,
									DBUS_TYPE_STRING,
									&str_wkn,
									DBUS_TYPE_STRING,
									&str_uuid,
									DBUS_TYPE_INT32,
									&countdown,
									DBUS_TYPE_INVALID);
			if (dbus_error_is_set(&error)) 
			{
				dbus_error_free(&error);
				continue;
			}
			if(0 == strncmp(str_wkn, bus_config.bus_wkn, strlen(str_wkn)))
			{
				if(g_dbus_con.ternimate_call)
					g_dbus_con.ternimate_call(str_uuid, countdown, g_dbus_con.callback_args);
				else
				{

				}
			}
			
		}
		else
		{
			//gp_dbus_connection was disconnected!
			break;
		}
	}
	return NULL;
}

static int check_process_name_string_illegal(const char * string)
{
	
	if(!string || strlen(string) == 0)
	{
		return -1;
	}
	while(!*string)
	{
		if(('a' <= *string && *string <= 'z') || ('A' <= *string && *string <= 'Z'))
		{
			string ++;
			continue;
		}
		else
			return -1;
	}
	return 0;
}
int process_feeddog_setup(const char * process_symbol, watchdog_terminate_callback callback, void *args)
{
	int ret_code = -1;
	if(!process_symbol || strlen(process_symbol) == 0)
	{
		
		return WATCHDOG_ERROR_INVALID_PROCESSID;
	}

	if(check_process_name_string_illegal(process_symbol) < 0)
	{
		return WATCHDOG_ERROR_INVALID_PARAM;
	}
	pthread_mutex_lock(&dbus_lock);
	if(g_dbus_con.dbus_inited)
	{
		pthread_mutex_unlock(&dbus_lock);
		return WATCHDOG_SUCCESS;
	}
	
	sprintf(bus_config.bus_wkn , "%s.%s", LORAGW_DBUS_NAME_PREFIX , process_symbol);
	sprintf(bus_config.interface_name , "%s.%s", LORAGW_DBUS_NAME_PREFIX , process_symbol);
	sprintf(bus_config.bus_obj_path , "%s/%s", LORAGW_DBUS_OBJPATH_PREFIX , process_symbol);
	
	ret_code = process_init_feedfog_dbus();
	if(WATCHDOG_SUCCESS != ret_code)
	{
		pthread_mutex_unlock(&dbus_lock);
		return ret_code;
	}
	if(callback)
	{
		if (0 != pthread_create(&g_dbus_con.g_thread_dbus_recv, NULL, module_dbus_msg_recving_loop, NULL)) {
	       process_uninit_feedfog_dbus();
		   pthread_mutex_unlock(&dbus_lock);
		   return WATCHDOG_ERROR_NO_MEM;
	    }
	}
	//g_dbus_con.processID = process;
	sprintf(g_dbus_con.process_symbol ,"%s", process_symbol);
	g_dbus_con.callback_args = args;
	g_dbus_con.ternimate_call = callback;
	g_dbus_con.dbus_exit = 0;
	g_dbus_con.dbus_inited = 1;
	
	pthread_mutex_unlock(&dbus_lock);
	
	return WATCHDOG_SUCCESS;
	
}
int process_uninit_feedfog_dbus()
{
    if (NULL != g_dbus_con.gp_dbus_connection) {
		//if use dbus_connection_open_private, we must call dbus_connection_close
		dbus_connection_close(g_dbus_con.gp_dbus_connection);

        dbus_connection_unref(g_dbus_con.gp_dbus_connection);
        g_dbus_con.gp_dbus_connection = NULL;
    }
    return 0;
}


int process_init_feedfog_dbus()
{
    DBusError dbus_error;
    dbus_error_init(&dbus_error);
#ifdef WATCHDOG_DEBUG_DBUS_USE_SESSION
    g_dbus_con.gp_dbus_connection = dbus_bus_get(DBUS_BUS_SESSION, &dbus_error);
#else
    //g_dbus_con.gp_dbus_connection = dbus_connection_open(bus_address, &dbus_error);
	//NOTE: change dbus_connection_open to dbus_connection_open_private
	g_dbus_con.gp_dbus_connection = dbus_connection_open_private(bus_address, &dbus_error);
#endif
    if (dbus_error_is_set(&dbus_error)) {
        return WATCHDOG_ERROR_IO;
    }
    if (NULL == g_dbus_con.gp_dbus_connection) {
        return WATCHDOG_ERROR_IO;
    }
    dbus_bus_register(g_dbus_con.gp_dbus_connection, &dbus_error);
    if (dbus_error_is_set(&dbus_error)) {
        dbus_error_free(&dbus_error);
		process_uninit_feedfog_dbus();
        return WATCHDOG_ERROR_IO;
    }

    int req_result = dbus_bus_request_name(g_dbus_con.gp_dbus_connection,
                                           bus_config.bus_wkn,
                                           DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                           &dbus_error);

    if (dbus_error_is_set(&dbus_error)) {
        if (req_result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
			/*
			log_e(WATCHDOG_UNITTEST_TAG "-DBUS",
                  "Well known name has been registered.\r\n"
                  "Name:    %s\r\n"
                  "Message: %s\r\n",
                  dbus_error.name, dbus_error.message);
                  */ 
            
        }
		process_uninit_feedfog_dbus();
        dbus_error_free(&dbus_error);
        return WATCHDOG_ERROR_IO;
    }

    return WATCHDOG_SUCCESS;
}

int process_feeddog_exit()
{
	pthread_mutex_lock(&dbus_lock);
	if(!g_dbus_con.dbus_inited)
	{
		pthread_mutex_unlock(&dbus_lock);
		return WATCHDOG_SUCCESS;
	}
	
	g_dbus_con.dbus_exit = 1;
	if(g_dbus_con.ternimate_call)
	{
		pthread_join(g_dbus_con.g_thread_dbus_recv, NULL);
	}
	process_uninit_feedfog_dbus();
	g_dbus_con.callback_args = NULL;
	g_dbus_con.ternimate_call = NULL;
	//g_dbus_con.processID = -1;
	
	g_dbus_con.dbus_inited = 0;
	pthread_mutex_unlock(&dbus_lock);
	return WATCHDOG_SUCCESS;
}

int thread_feeddog_with_operation(const char * process_symbol,const char* threadID,unsigned int count, watchdog_timeout_opreation_et opr)
{
	int ret;
	if(!process_symbol || 0 == strlen(process_symbol))
	{
		return WATCHDOG_ERROR_INVALID_PARAM;
	}
	if(!threadID || 0 == strlen(threadID))
	{
		return WATCHDOG_ERROR_INVALID_PARAM;
	}
	pthread_mutex_lock(&dbus_lock);
	if(!g_dbus_con.dbus_inited)
	{	
		pthread_mutex_unlock(&dbus_lock);
		ret = process_feeddog_setup(process_symbol, NULL, NULL);
		if(ret != WATCHDOG_SUCCESS)
			return ret;
	}
	else
	{
		pthread_mutex_unlock(&dbus_lock);
		if(strcmp(g_dbus_con.process_symbol, process_symbol) != 0)
		{
			return WATCHDOG_ERROR_INVALID_PARAM;
		}
	}
	if(opr > OPR_RESTART_PROCESS_ONLY)
		opr = OPR_RESTART_PROCESS_ONLY;
	
	//todo : what to do while count is too large
	DBusMessage * dbus_msg = watchdog_new_feeddog_signal(bus_config.bus_wkn, \
									bus_config.bus_obj_path,\
									threadID, (int)count , (int)opr);
	if(!dbus_msg)
	{
		return WATCHDOG_ERROR_DBUS_ALLOC;
	}

	if (FALSE == dbus_connection_send(g_dbus_con.gp_dbus_connection, dbus_msg, NULL)) {
        dbus_message_unref(dbus_msg);
        return WATCHDOG_ERROR_DBUS_SEND;
    }
    dbus_message_unref(dbus_msg);

	return WATCHDOG_SUCCESS;
	
}

int thread_feeddog(const char * process_symbol,const char* threadID,unsigned int count)
{
	return thread_feeddog_with_operation(process_symbol, threadID, count, OPR_REBOOT_SYSTEM);
}

int thread_feeddog_periodically(const char * process_symbol, const char * threadID, unsigned int feed_interval, unsigned int feed_count, void * time_keeper)
{
	struct timespec monotonic_now;
	if(!process_symbol || strlen(process_symbol) == 0)
	{
		return WATCHDOG_ERROR_INVALID_PARAM;
	}
	if(!threadID || strlen(threadID) == 0 || !time_keeper)
	{
		return WATCHDOG_ERROR_INVALID_PARAM;
	}
	/* for feeddog safely */
	if(feed_interval == 0 || feed_count - feed_interval < 5)
	{
		return WATCHDOG_ERROR_INVALID_PARAM;
	}
	struct timespec *holder = (struct timespec *)time_keeper;

	if (0 != clock_gettime(CLOCK_MONOTONIC, &monotonic_now))
	{
		return WATCHDOG_ERROR_IO;
	}
	if (monotonic_now.tv_sec - holder->tv_sec >= feed_interval)
	{
		if (0 != clock_gettime(CLOCK_MONOTONIC, holder))
		{
			return WATCHDOG_ERROR_IO;
		}
		return thread_feeddog(process_symbol, threadID, feed_count);
	}
	
	return WATCHDOG_SUCCESS;
}

int thread_cancel_feeddog(const char * process_symbol, const char * threadID)
{
	int ret = -1;
	pthread_mutex_lock(&dbus_lock);
	if(!g_dbus_con.dbus_inited)
	{
		pthread_mutex_unlock(&dbus_lock);
		return WATCHDOG_ERROR_BUS_INVALID;
	}
	pthread_mutex_unlock(&dbus_lock);
	if(!process_symbol || 0 == strlen(process_symbol))
	{
		return WATCHDOG_ERROR_INVALID_PARAM;
	}
	if(!threadID || 0 == strlen(threadID))
	{
		return WATCHDOG_ERROR_INVALID_PARAM;
	}

	if(strcmp(g_dbus_con.process_symbol , process_symbol) != 0)
	{
		return WATCHDOG_ERROR_BUS_INVALID;
	}
	
	return watchdog_cancel_feeddog(g_dbus_con.gp_dbus_connection,\
							bus_config.bus_wkn,\
							bus_config.bus_obj_path,\
							threadID);
	
}


