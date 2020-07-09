#include "loragw_interface_common.h"
#include <pthread.h>
#include "linux-list.h"
#include <errno.h>

typedef struct _ipc_method_call_dispatch_info_tag {
    struct list_head list_node;
    uint32_t serial_id;

    pthread_cond_t cond;
    DBusMessage *reply_msg;
} _MethodCallDispatchInfo;


static int ipc_uninit_dbus();
static int ipc_dbus_init();
static int get_method_array_size();

static pthread_mutex_t mutex_method_call_dispatchlist;
static _MethodCallDispatchInfo _method_call_dispatch_list ;
void *module_msg_recving_loop(void *args);

typedef struct{
	int dbus_inited ;
	DBusConnection *gp_dbus_connection;
	int dbus_exit;
	pthread_t g_thread_dbus_recv;
    const char *wkn_name;
    const char *obj_path;
    const char *interface_name;

    int msg_max;
    pthread_mutex_t lock;
}dbus_connecttion_st;

dbus_connecttion_st  g_dbus_ipc = {0,NULL,0};

dbus_message_callback_st dbus_msg_call[IPC_MSG_TYPE_MAX] ;



static void MethodCallDispatchInfo_free(_MethodCallDispatchInfo *instance)
{
    if (instance) {
        pthread_cond_destroy(&instance->cond);

        if (instance->reply_msg) {
            dbus_message_unref(instance->reply_msg);
            instance->reply_msg = NULL;
        }
        instance->serial_id = 0;
        free(instance);
        instance = NULL;
    }
}
static _MethodCallDispatchInfo * MethodCallDispatchInfo_create()
{
    _MethodCallDispatchInfo *instance = (_MethodCallDispatchInfo *) malloc(sizeof(
                        _MethodCallDispatchInfo));
    if (instance) {
        pthread_cond_init(&instance->cond, NULL);

        instance->reply_msg = NULL;
        instance->serial_id = 0;
        INIT_LIST_HEAD(&instance->list_node);
    }
    return instance;
}

int loragw_ipc_setup(void * args)
{
    dbus_params_st * params = (dbus_params_st * )args;
    if(!params) {
        return LORA_IPC_ERROR_INVALID_PARAM;
    }
    int ret = LORA_IPC_SUCCESS;
    if(g_dbus_ipc.dbus_inited) {
        
        return LORA_IPC_SUCCESS;
    }
    g_dbus_ipc.wkn_name = strdup(params->wkn_name);
    g_dbus_ipc.obj_path = strdup(params->obj_path);
    g_dbus_ipc.interface_name = strdup(params->interface_name);
    if(!g_dbus_ipc.wkn_name || !g_dbus_ipc.obj_path || !g_dbus_ipc.interface_name) {
        ret =  LORA_IPC_ERROR_NO_MEM;
        goto error1;
    }
    ret = ipc_dbus_init();
    if(ret < 0) {
        goto error1;
    }

    g_dbus_ipc.dbus_exit = 0;

    if (0 != pthread_create(&g_dbus_ipc.g_thread_dbus_recv, NULL, module_msg_recving_loop, NULL)) {
        ipc_uninit_dbus();
        ret = LORA_IPC_ERROR_NO_MEM;
        goto error1;
    }
    pthread_mutex_init(&g_dbus_ipc.lock, NULL);
    pthread_mutex_init(&mutex_method_call_dispatchlist, NULL);

    pthread_mutex_lock(&g_dbus_ipc.lock);
    g_dbus_ipc.msg_max = 0;
    memset(dbus_msg_call, 0,  sizeof(dbus_msg_call));

    INIT_LIST_HEAD(&_method_call_dispatch_list.list_node);
    
    pthread_mutex_unlock(&g_dbus_ipc.lock);

    return LORA_IPC_SUCCESS;

error1:
    if(g_dbus_ipc.wkn_name)
        free((void *)g_dbus_ipc.wkn_name);
    if(g_dbus_ipc.obj_path)
        free((void *)g_dbus_ipc.obj_path);
    if(g_dbus_ipc.interface_name)
        free((void *)g_dbus_ipc.interface_name);

    return ret;
}
static int get_method_array_size()
{
    int ret = 0;
    pthread_mutex_lock(&g_dbus_ipc.lock);
    ret = g_dbus_ipc.msg_max;
    pthread_mutex_unlock(&g_dbus_ipc.lock);
    return ret;
}

static int ipc_dbus_init()
{
    DBusError dbus_error;
    dbus_error_init(&dbus_error);

    g_dbus_ipc.gp_dbus_connection = dbus_connection_open(bus_address, &dbus_error);

    if (dbus_error_is_set(&dbus_error)) {
        return LORA_IPC_ERROR_IO;
    }
    if (NULL == g_dbus_ipc.gp_dbus_connection) {
        return LORA_IPC_ERROR_IO;
    }
    dbus_bus_register(g_dbus_ipc.gp_dbus_connection, &dbus_error);
    if (dbus_error_is_set(&dbus_error)) {
        dbus_error_free(&dbus_error);
		ipc_uninit_dbus();
        return LORA_IPC_ERROR_IO;
    }

    int req_result = dbus_bus_request_name(g_dbus_ipc.gp_dbus_connection,
                                           g_dbus_ipc.wkn_name,
                                           DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                           &dbus_error);

    if (dbus_error_is_set(&dbus_error)) {
        if (req_result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
			
			ipc_log_err("-DBUS",
                  "Well known name has been registered.\r\n"
                  "Name:    %s\r\n"
                  "Message: %s\r\n",
                  dbus_error.name, dbus_error.message);
                  
            
        }
		ipc_uninit_dbus();
        dbus_error_free(&dbus_error);
        return LORA_IPC_ERROR_IO;
    }
    g_dbus_ipc.dbus_inited = 1;
    return LORA_IPC_SUCCESS;
}

static int loragw_ipc_process_method_call_return(DBusMessage * message) {

    int ret = LORA_IPC_ERROR_INVALID_DATA;
    uint32_t reply_serial = dbus_message_get_reply_serial(message);
    _MethodCallDispatchInfo *pos = NULL, *n = NULL;
    pthread_mutex_lock(&mutex_method_call_dispatchlist);
    list_for_each_entry_safe(pos, n, &_method_call_dispatch_list.list_node, list_node) {
        if (reply_serial == pos->serial_id) {
            //log_debug( "Dispatch found: serial_id=%d, reply_id=%d\r\n", pos->serial_id, reply_serial);
            pos->reply_msg = dbus_message_ref(message);
            pthread_cond_signal(&pos->cond);
            ret = LORA_IPC_SUCCESS;
        }
    }
    pthread_mutex_unlock(&mutex_method_call_dispatchlist);
    return ret;
}

static int ipc_uninit_dbus()
{
    if (NULL != g_dbus_ipc.gp_dbus_connection) {
        dbus_connection_unref(g_dbus_ipc.gp_dbus_connection);
        g_dbus_ipc.gp_dbus_connection = NULL;
    }
    g_dbus_ipc.dbus_inited = 0;
    return LORA_IPC_SUCCESS;
}

int loragw_ipc_exit()
{

    if(!g_dbus_ipc.dbus_inited)
	{
		return LORA_IPC_SUCCESS;
	}
	
	g_dbus_ipc.dbus_exit = 1;

	pthread_join(g_dbus_ipc.g_thread_dbus_recv, NULL);

	ipc_uninit_dbus();
    
    pthread_mutex_lock(&g_dbus_ipc.lock);

    if(g_dbus_ipc.wkn_name)
        free((void *)g_dbus_ipc.wkn_name);
    if(g_dbus_ipc.obj_path)
        free((void *)g_dbus_ipc.obj_path);
    if(g_dbus_ipc.interface_name)
        free((void *)g_dbus_ipc.interface_name);


    for(int i = 0 ; i < g_dbus_ipc.msg_max; i++ ) {
        if(dbus_msg_call[g_dbus_ipc.msg_max].name) {
            free((void *)dbus_msg_call[g_dbus_ipc.msg_max].name);
            dbus_msg_call[g_dbus_ipc.msg_max].name = NULL;
            dbus_msg_call[g_dbus_ipc.msg_max].call = NULL;
        }
    }
    g_dbus_ipc.msg_max = 0;

    pthread_mutex_unlock(&g_dbus_ipc.lock);

    
    pthread_mutex_destroy(&g_dbus_ipc.lock);
    
    pthread_mutex_destroy(&mutex_method_call_dispatchlist);

	return LORA_IPC_SUCCESS;
}


void *module_msg_recving_loop(void *args)
{
	DBusError error;
	char listen_str[256];
	DBusMessage *message = NULL;
    int ret = 0;
	if(!g_dbus_ipc.gp_dbus_connection)
	{
		return NULL;
	}

    sprintf(listen_str, "type='signal',interface='%s'",\
							g_dbus_ipc.interface_name);
	dbus_error_init(&error);
	dbus_bus_add_match(g_dbus_ipc.gp_dbus_connection, listen_str ,&error);
	if (dbus_error_is_set(&error)) 
	{
		dbus_error_free(&error);
		return NULL;
	}
	while(!g_dbus_ipc.dbus_exit)
	{
		//block while recving the signal
		if(dbus_connection_read_write(g_dbus_ipc.gp_dbus_connection, 1000))
		{
            //ipc_log_debug("dbus ipc running!!!");
	        message = dbus_connection_pop_message(g_dbus_ipc.gp_dbus_connection);
	        if (message == NULL) {
	            continue;
	        }
            int messageType = dbus_message_get_type(message);
            if(DBUS_MESSAGE_TYPE_METHOD_CALL == messageType || DBUS_MESSAGE_TYPE_SIGNAL == messageType)
            {
                const char * message_name = dbus_message_get_member(message);
                if(message_name == NULL)
                {
                    ipc_log_err( "get method name error!");
                    dbus_message_unref(message);
                    continue;
                }
                int i = 0;
                //ipc_log_debug("incoming method call or signal %s !!!\n", message_name);
                int num = get_method_array_size();
                for(i=0;i<num;i++)
                {
                    pthread_mutex_lock(&g_dbus_ipc.lock);
                    if(0 == strncmp(dbus_msg_call[i].name, message_name,strlen (message_name)))
                    {
                        //ipc_log_debug("find the callback for %s !!!\n", message_name);
                        pthread_mutex_unlock(&g_dbus_ipc.lock);
                        ret = dbus_msg_call[i].call(g_dbus_ipc.gp_dbus_connection,message);
                        if(ret != LORA_IPC_SUCCESS)
                        {
                            ipc_log_err("%s callback return error %d !!\n", message_name , ret);
                        }  
                        break; 
                    }
                    pthread_mutex_unlock(&g_dbus_ipc.lock);
                }
                if( i == num)
                {
                    ipc_log_info("do not find message %s process call !\n", message_name);
                }
                dbus_message_unref(message);
            }
            else if(DBUS_MESSAGE_TYPE_METHOD_RETURN == messageType)
            {
                if( (ret = loragw_ipc_process_method_call_return(message) ) < 0 ) {

                    ipc_log_info("do not find method call for this return message !");
                }

                dbus_message_unref(message);
            }
            else if(DBUS_MESSAGE_TYPE_ERROR)
            {
                
                if((ret = loragw_ipc_process_method_call_return(message) ) < 0 ) {
                    ipc_log_info("do not find method call for this error message!");
                }
                
                dbus_message_unref(message);
                continue;
            }
            else {
                dbus_message_unref(message);
                
                continue;
            }
		}
		else
		{
			
            ipc_log_err("dbus was disconnected !!! breaking the msg recving loop!!!\n");
			break;
		}
	}
	return NULL;
}

int loragw_ipc_setup_msg_callback(const char * msg, method_signal_call callback)
{
    if(!msg || strlen(msg) == 0 || !callback) {
        return LORA_IPC_ERROR_INVALID_PARAM;
    }

    pthread_mutex_lock(&g_dbus_ipc.lock);
    if(g_dbus_ipc.msg_max >= IPC_MSG_TYPE_MAX) {
        pthread_mutex_unlock(&g_dbus_ipc.lock);
        ipc_log_err("strdup failed!!");
        return LORA_IPC_ERROR_NO_MEM;
    }
    dbus_msg_call[g_dbus_ipc.msg_max].name = strdup(msg);

    if(!dbus_msg_call[g_dbus_ipc.msg_max].name) {
        pthread_mutex_unlock(&g_dbus_ipc.lock);
        ipc_log_err("strdup failed!!");
        return LORA_IPC_ERROR_NO_MEM;
    }
    dbus_msg_call[g_dbus_ipc.msg_max].call = callback;
    g_dbus_ipc.msg_max++;
    pthread_mutex_unlock(&g_dbus_ipc.lock);
    return LORA_IPC_SUCCESS;
}

void* loragw_ipc_send_with_reply_and_block(void * message, int wait_ms, void *error)
{
    if(!message || !error) {
        return NULL;
    }
    DBusMessage *pmessage = NULL;
    DBusMessage *msgReply = NULL;
    DBusError * perror = (DBusError *)error;
    int ret = 0;
    pmessage = (DBusMessage *)message;

    _MethodCallDispatchInfo *dispatch_info = MethodCallDispatchInfo_create();
    if (NULL == dispatch_info) {
        
        perror->name = "iot.gateway.ipc.send_reply_block";
        perror->message = "Can not allocate memory.";
        return NULL;
    }
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += wait_ms / 1000;
    timeout.tv_nsec += (wait_ms % 1000) * 1000000;
    timeout.tv_sec += (timeout.tv_nsec) / 1000000000;
    timeout.tv_nsec %= 1000000000;

    pthread_mutex_lock(&mutex_method_call_dispatchlist);
    list_add_tail(&dispatch_info->list_node, &_method_call_dispatch_list.list_node);
    ret = dbus_connection_send(g_dbus_ipc.gp_dbus_connection, pmessage, &dispatch_info->serial_id);
    if ( !ret ) {
        list_del(&dispatch_info->list_node);
        MethodCallDispatchInfo_free(dispatch_info);
        dispatch_info = NULL;
        pthread_mutex_unlock(&mutex_method_call_dispatchlist);
        return NULL;
    }

    //dbus_connection_flush(g_dbus_ipc.gp_dbus_connection);

    ret = pthread_cond_timedwait(&dispatch_info->cond, &mutex_method_call_dispatchlist, &timeout);

    list_del(&dispatch_info->list_node);

    pthread_mutex_unlock(&mutex_method_call_dispatchlist);

    if (0 != ret) {
        if (ETIMEDOUT == ret) {
            perror->name = "iot.gateway.ipc.send_reply_block";
            perror->message = "Wait Timed out";
        } else {
            perror->name = "iot.gateway.ipc.send_reply_block";
            perror->message = "Unknown error.";
        }
        MethodCallDispatchInfo_free(dispatch_info);
        dispatch_info = NULL;
        return NULL;
    }
    else {
        msgReply = dbus_message_ref(dispatch_info->reply_msg);
        MethodCallDispatchInfo_free(dispatch_info);
        dispatch_info = NULL;
        return (void *)msgReply;

    }

    return NULL;
}

bool loragw_ipc_send(void * message,  uint32_t *serial) 
{
    return dbus_connection_send(g_dbus_ipc.gp_dbus_connection, (DBusMessage *)message, serial);
}

uint32_t loragw_ipc_request_pid_by_wkn_block(const char * wkn_name)
{
    uint32_t pid_ret = ~(0u);

    if (NULL == wkn_name) {
        return pid_ret;
    }
    DBusError dbus_error;
    dbus_error_init(&dbus_error);

    DBusMessage *mc_getpid = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
                             DBUS_PATH_DBUS,
                             DBUS_INTERFACE_DBUS,
                             "GetConnectionUnixProcessID");

    if (NULL == mc_getpid) {
        ipc_log_err( "Unable to get method_call.\r\n");
        return pid_ret;
    }

    dbus_message_append_args(mc_getpid, DBUS_TYPE_STRING, &wkn_name, DBUS_TYPE_INVALID);
    DBusMessage *mc_ret = loragw_ipc_send_with_reply_and_block(mc_getpid,
                          2000,
                          &dbus_error);
    dbus_message_unref(mc_getpid);
    if (dbus_error_is_set(&dbus_error)) {
        ipc_log_err(
              "Method Call failed: GetConnectionUnixProcessID(bus_name).\r\n"
              "Error name:    %s\r\n"
              "Error Message: %s\r\n",
              dbus_error.name, dbus_error.message);
        dbus_error_free(&dbus_error);
        if (mc_ret) {
            dbus_message_unref(mc_ret);
        }
        return pid_ret;
    }

    if (NULL == mc_ret) {
        return pid_ret;
    }

    if (dbus_message_get_type(mc_ret) == DBUS_MESSAGE_TYPE_ERROR) {
        const char *dbus_error_ret_string;
        dbus_message_get_args(mc_ret, &dbus_error, DBUS_TYPE_STRING, &dbus_error_ret_string, DBUS_TYPE_INVALID);
        if (dbus_error_is_set(&dbus_error)) {
            ipc_log_err(
                  "  Unable to get returned error:\r\n"
                  "  Error name:    %s\r\n"
                  "  Error Message: %s\r\n",
                  dbus_error.name,
                  dbus_error.message);
            dbus_error_free(&dbus_error);
        }
        ipc_log_err( "  Got error message: %s\r\n", dbus_error_ret_string);
    } else if (dbus_message_get_type(mc_ret) == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
        dbus_message_get_args(mc_ret, &dbus_error, DBUS_TYPE_UINT32, &pid_ret, DBUS_TYPE_INVALID);
        if (dbus_error_is_set(&dbus_error)) {
            ipc_log_err(
                  "  Unable to get returned message:\r\n"
                  "  Error name:    %s\r\n"
                  "  Error Message: %s\r\n",
                  dbus_error.name,
                  dbus_error.message);
            dbus_error_free(&dbus_error);
        }
    }

    dbus_message_unref(mc_ret);
    return pid_ret;
}