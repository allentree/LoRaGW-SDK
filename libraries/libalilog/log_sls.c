#include "aos_log.h"
#include "aos_util.h"
#include "aos_string.h"
#include "aos_status.h"
#include "log_auth.h"
#include "log_util.h"
#include "log_api.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>

typedef const char cchar;

#define  LOG_ENDPOINT           "https://cn-hangzhou.log.aliyuncs.com"
#define  ACCESS_KEY_ID          "Your Key Id"
#define  ACCESS_KEY_SECRET      "Your Secret"
#define  PROJECT_NAME           "iot-edge-compute"
#define  LOGSTORE_NAME_APP      "edge-aep-app"
#define  LOGSTORE_NAME_CMP      "edge-cmp"
#define  LOGSTORE_NAME_RDBG     "edge-aep-remote-debug"
#define  LOGSTORE_NAME_DB       "edge-aep-db"

static int g_flag_sls = 0;

static char g_endpoint[128] = {0};
static char g_access_key[64] = {0};
static char g_access_secret[64] = {0};
static char g_project_name[64] = {0};
static char g_logstore[64] = {0};

int log_sls_init(cchar *endpoint, cchar *access_key, cchar *secret, cchar *project)
{
    if(!endpoint || !access_key || !secret || !project){
        g_flag_sls = 0;
        return -1;
    } 

    if (aos_http_io_initialize("linux-x86_64", 0) != AOSE_OK) {
        g_flag_sls = 0;
        return -1;
    }
    g_flag_sls = 1;
    memset(g_endpoint, 0, sizeof(g_endpoint)); 
    memset(g_access_secret, 0, sizeof(g_access_secret)); 
    memset(g_access_key, 0, sizeof(g_access_key)); 
    memset(g_project_name, 0, sizeof(g_project_name)); 
    
    snprintf(g_endpoint, sizeof(g_endpoint), "%s", endpoint);
    snprintf(g_access_key, sizeof(g_access_key), "%s", access_key);
    snprintf(g_access_secret, sizeof(g_access_secret), "%s", secret);
    snprintf(g_project_name, sizeof(g_project_name), "%s", project);

    return 0;
}

static char *int2str(char *buf, int len, long v)
{
    if (!buf) {
        return NULL;
    }
    memset(buf, 0, len);
    snprintf(buf, len, "%ld", v);
    return buf;
}

int log_sls_print(cchar *uuid,cchar *m, cchar *t, cchar *lvl, cchar *f, cchar *func,
        int l, cchar *log, long timestamp, cchar *store)
{   
    int ret = -1; 
    char line[33] = {0};
    char ts[65] = {0};
    aos_status_t *s = NULL;
    log_group_builder* bder = NULL;

    if(!store) 
        return ret;
    bder = log_group_create();
    
    if(uuid) 
        add_source(bder,uuid,strlen(uuid));
    
    if(m) 
        add_topic(bder,m,strlen(m));
    
    add_log(bder);
    
    if(t) 
        add_log_key_value(bder, "tag", strlen("tag"), t, strlen(t));
    
    if(lvl) 
        add_log_key_value(bder, "level", strlen("level"), lvl, strlen(lvl));
    
    if(f) 
        add_log_key_value(bder, "file_name", strlen("file_name"), f, strlen(f));
    
    if(func) 
        add_log_key_value(bder, "func_name", strlen("func_name"), func, strlen(func));
   
    if(l){
        int2str(line,sizeof(line),l);
        add_log_key_value(bder, "line", strlen("line"),line,strlen(line));
    }
    
    if(log)
        add_log_key_value(bder, "content", strlen("content"), log, strlen(log));
   
    if(timestamp){
        int2str(ts,sizeof(ts),timestamp);
        add_log_key_value(bder, "timestamp", strlen("timestamp"),ts,strlen(ts));
    }

    s = log_post_logs_from_proto_buf(g_endpoint, g_access_key, g_access_secret,NULL, g_project_name, store, bder);
    
    if (!aos_status_is_ok(s)) 
        printf("post msg failed: %d, %s, %s, %s \n",s->code,s->error_code,s->error_msg,s->req_id);
    else
        ret = 0;
    
    log_group_destroy(bder);

    return ret;
}

void log_sls_destroy()
{
    aos_http_io_deinitialize();
}


int main()
{
    log_sls_init(LOG_ENDPOINT, ACCESS_KEY_ID, ACCESS_KEY_SECRET, PROJECT_NAME);

    log_sls_print(NULL,"OTA","init","INF", "init_func.c", "init_func",
                100, "start to init ota module",time(NULL),LOGSTORE_NAME_APP);

    log_sls_print("uuid_dev_2","FOTA","destroy","DBG", "dest_func.c", "dest_func",
                100, "start to init ota module",time(NULL),LOGSTORE_NAME_CMP);

    log_sls_print("uuid_dev_3","Bridge","init","INF", "bridge_func.c", "init_func",
                100, "start to init ota module",time(NULL),LOGSTORE_NAME_RDBG);

    log_sls_print("uuid_dev_4","cmp","init","INF", "init_func.c", "init_func",
                100, "start to init ota module",time(NULL),LOGSTORE_NAME_DB);

    log_sls_destroy();
    return 0;
}





