#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>
#include <semaphore.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_PATH_LENGTH     128
#define MAX_FILENAME_LENGTH 512

static FILE         *g_fp = NULL;
static int          g_flag_file_init = 0;
static pthread_mutex_t g_file_locker;
static int          g_log_file_size = 0;
static char         g_file_name[MAX_FILENAME_LENGTH] = {0};
static unsigned int g_log_index = 0;
char *g_log_prefix = "log_";
const char *g_log_postfix = ".txt";

extern char *g_dir_name;
extern unsigned int g_single_size;

static void save_last_file()
{
    if(g_fp){
        fclose(g_fp);
        g_fp = NULL;
        g_log_file_size = 0;    
    }
}

static char *gen_log_name(char *file_name, int len)
{
    if(!file_name || len <= 0)   
        return NULL;
 
    time_t timep;
    struct tm now;
    
    time(&timep);
    localtime_r(&timep,&now);
  
    memset(file_name,0,len);
    if(g_dir_name)
        snprintf(file_name,len,"%s",g_dir_name);

    if(g_log_prefix) 
        snprintf(file_name + strlen(file_name),
                len - strlen(file_name),"%s",g_log_prefix);
    //add time
    strftime(file_name + strlen(file_name),
            len - strlen(file_name),"%Y-%m-%d-%H-%M-%S",&now);

    if(g_log_postfix)
        snprintf(file_name + strlen(file_name),
                len - strlen(file_name),"-%lu-%d%s",timep,
                ++g_log_index,g_log_postfix); 

    printf("new file name:  %s\n",file_name);
    return file_name; 
}

static void create_symlink(char *file_name)
{
    char cmd[512] = {0};
    char mod_dir[512]= {0};
    char *log_name = NULL;
    char *mod_name = NULL;
    char *p = NULL;

    strncpy(mod_dir, g_dir_name, sizeof(mod_dir) - 1 );
    p = strrchr(mod_dir, '/');
    if (NULL != p) {
        *p = 0;
    }

    mod_name = strrchr(mod_dir, '/');
    if (NULL == mod_name) {
        mod_name = mod_dir;
    } else {
        mod_name = mod_name + 1;
    }

    log_name = strrchr(file_name, '/');
    if (NULL == log_name) {
        log_name = file_name;
    } else {
        log_name = log_name + 1;
    }

    snprintf(cmd,sizeof(cmd),"ln -sf %s %s/%s.INFO",log_name,g_dir_name,mod_name);
    system(cmd);
}

static int create_new_file()
{
    char *file_name = gen_log_name(g_file_name, sizeof(g_file_name));

    save_last_file();
    g_fp = fopen(file_name,"a+");

    if(!g_fp){
        printf("failed to create file: %s:%s\n",file_name,strerror(errno));
        return -1;
    }
    setbuf(g_fp,NULL);
    g_log_file_size = 0;    
    create_symlink(file_name);

    return 0;
}

static void __add_content(const char *log)
{
    if(g_log_file_size + strlen(log) > g_single_size*1024*1024)
        create_new_file();

    if(g_fp){
        fwrite(log,1,strlen(log),g_fp);
        g_log_file_size += strlen(log);
    }
}

int log_fs_init()
{
    int ret = 0;
    if(g_flag_file_init == 1) 
        return 0;

    ret = pthread_mutex_init(&g_file_locker,NULL);
    if(ret != 0){
        printf("log fs init failed.\n");
        return -1;
    } 

    pthread_mutex_lock(&g_file_locker);
    ret = create_new_file();
    if(ret != 0){
        pthread_mutex_unlock(&g_file_locker);
        return -1;
    }
    g_flag_file_init = 1; 
    pthread_mutex_unlock(&g_file_locker);
    return 0;
}

void log_fs_add_content(const char *str)
{
    if(!str || (!g_flag_file_init && 0 != log_fs_init()))
        return;

    pthread_mutex_lock(&g_file_locker);
    __add_content(str);
    pthread_mutex_unlock(&g_file_locker);
}

void log_fs_destroy()
{
    if(g_flag_file_init != 1)
        return;
   
    pthread_mutex_lock(&g_file_locker);
    save_last_file();
    pthread_mutex_unlock(&g_file_locker);
    pthread_mutex_destroy(&g_file_locker);
}


