#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include "log.h"

//default storage is 40 MByte.
#ifndef DEFAULT_STORAGE_SIZE
#define DEFAULT_STORAGE_SIZE 40
#endif

//default size of each log file is 5 MByte.
#ifndef DEFAULT_FILE_SIZE  
#define DEFAULT_FILE_SIZE   5 
#endif

#ifndef OSS_FILE
#define OSS_FILE
#endif

unsigned long long g_total_size = DEFAULT_STORAGE_SIZE;
unsigned int g_single_size = DEFAULT_FILE_SIZE;
static unsigned long long g_cur_dir_size = 0;
char *g_dir_name = NULL;

extern void log_fs_add_content(const char *str);
extern void log_fs_destroy();
extern int log_fs_init();

static unsigned long long get_dir_size(cchar *dir)
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;
    unsigned long long total_size=0;
    char sub_dir[512];
    if (!dir || !(dp = opendir(dir)))
        return 0; 
    
    if(-1 == lstat(dir, &statbuf)){
        closedir(dp);   
        return 0;
    }
    total_size+=statbuf.st_size;

    while ((entry = readdir(dp)) != NULL){
        snprintf(sub_dir,sizeof(sub_dir), "%s/%s", dir, entry->d_name);
        if(-1 == lstat(sub_dir, &statbuf))
            break;
        
        if (S_ISDIR(statbuf.st_mode)){
            if (strcmp(".", entry->d_name) == 0 ||
                strcmp("..", entry->d_name) == 0)
                continue;
            total_size += get_dir_size(sub_dir);
        }else
            total_size+=statbuf.st_size;
    }
    closedir(dp);   
    return total_size;
}

static void create_dir(cchar *dir)
{
    char cmd[256] = {0};
    snprintf(cmd,sizeof(cmd),"mkdir -p %s",dir);
    system(cmd);
    
    if(g_dir_name)
        free(g_dir_name);

    g_dir_name = (char *)malloc(strlen(dir)+2);
    if(!g_dir_name)
        return;

    memset(g_dir_name,0,strlen(dir)+2);
    strcpy(g_dir_name,dir);
    strcat(g_dir_name,"/");
    
    g_cur_dir_size = get_dir_size(g_dir_name);
}

static int remove_file(cchar *dir,cchar *file)
{
    char path[512] = {0};
    int ret = 0;
    if(!dir || !file || strlen(file) <= 0){
        return -1;
    }

    snprintf(path,sizeof(path),"%s/%s",dir,file);
    ret = remove(path);
    return ret;
}

extern char *g_log_prefix;
extern const char *g_log_postfix;
static unsigned long get_log_utc(const char *file, unsigned long *index)
{
    if(!file)
        return 0;
    //format: .//log_sample_x/log_2018-02-05-20-21-42-4444444-4.txt
    char *tmp = NULL;
    unsigned long utc = 0;
    int i = 0;

    tmp = strstr(file,g_log_prefix);
   
    if(!tmp)
        return 0;
   
    while(tmp){
        tmp = strchr(tmp,'-');
        if(!tmp)
            break;
        tmp += 1;
        i++;
        if(i == 6)
            utc = atol(tmp);
        else if(i == 7){
            *index = atol(tmp);
            break;
        }
    }

    return utc;
}


static unsigned long long del_old_logs(cchar *dir)
{
    DIR *dp = NULL;
    struct dirent *entry;
    struct stat statbuf;
    unsigned long long size = 0;
    time_t min_date = 0x7fffffff;
    char del_file_name[512] = {0};
    char sub_dir[512];
    unsigned long long dir_size = 0;
    unsigned long index = 0;
    unsigned long last_index = 0;
    unsigned long utc = 0;
    if (!dir || !(dp = opendir(dir))){
        printf("failed to open dir: %s\n",dir); 
        return 0; 
    }
    
    if(-1 == lstat(dir, &statbuf)){
        printf("failed to stat dir: %s, msg: %s \n",dir,strerror(errno)); 
        closedir(dp);
        return 0;
    }
    while ((entry = readdir(dp)) != NULL){
        snprintf(sub_dir,sizeof(sub_dir), "%s/%s", dir, entry->d_name);
        if(-1 == lstat(sub_dir, &statbuf)){
            printf("failed to stat dir: %s, msg: %s, return\n",dir,strerror(errno)); 
            closedir(dp);
            return 0;
        }

        if (!S_ISREG(statbuf.st_mode))
            continue;
        
        dir_size += statbuf.st_size;
        //only delete file prefixed by "log_"
        utc = get_log_utc(entry->d_name,&index);
        printf("file: %s, timestamp: %ld, min_date: %ld, size: %ld\n",entry->d_name,utc,min_date,statbuf.st_size);
        if(strstr(entry->d_name,g_log_prefix)){
            if(utc < min_date){
                min_date = utc;
                last_index = index;
                size = statbuf.st_size;
                memset(del_file_name,0,sizeof(del_file_name));
                strcpy(del_file_name,entry->d_name);
            }else if(utc == min_date){
                if(index < last_index){
                    last_index = index;
                    size = statbuf.st_size;
                    memset(del_file_name,0,sizeof(del_file_name));
                    strcpy(del_file_name,entry->d_name);
                } 
            }
        }
    }
    closedir(dp);
    
    return dir_size - (remove_file(g_dir_name,del_file_name) == 0 ? size : 0);
}

void log_file_print(int lvl, const char *str)
{
    if(!str)
        return;
    
    log_fs_add_content(str);
    g_cur_dir_size += strlen(str) + 1;

    if(g_cur_dir_size >= g_total_size*1024*1024){
        g_cur_dir_size = del_old_logs(g_dir_name);
    }
}

uint8_t log_file_init(cchar *dir, int total_size, int single_size)
{
    if(!dir){
        printf("log file init error: dir should not be NULL. \n");
        return -1;
    } 

    if(total_size < single_size){
        printf("total size should be larger than single_size.\n");
        return -2;
    }

    create_dir(dir);
    g_total_size = total_size > 0 ? total_size : DEFAULT_STORAGE_SIZE;
    g_single_size = single_size > 0 ? single_size : DEFAULT_FILE_SIZE;

    log_fs_init();

    printf("log file init ok, total size: %lld, single file size: %d\n", g_total_size, g_single_size);
    return 0;
}

#ifdef OSS_FILE
extern uint8_t log_file_upload();
extern void log_file_oss_destroy();
#endif

void log_file_destroy()
{
    if(g_dir_name){
        free(g_dir_name); 
        g_dir_name = NULL; 
    }

#ifdef OSS_FILE
    log_file_oss_destroy();
#endif

    printf("log file destroy\n");
    log_fs_destroy();
}

