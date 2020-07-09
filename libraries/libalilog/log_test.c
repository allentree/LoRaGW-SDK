#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include "log.h"

void *thread_gen_logs(void *arg)
{
    int i = 0;
    int *cnt = (int *)arg;

    for (i = 0; i < *cnt; i++) {
        log_d("accs", "%s", "accs module init ok\n");
        log_w("alcs", "%s", "alcs module init ok\n");
        log_i("fota", "%s", "fota module init ok\n");
        log_w("cota", "%s", "cota module init failed.\n");
        log_e("asr", "%s", "helo log system\n");
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int i = 0;
    int max_thread_cnt = 1;
    int max_log_cnt = 1; 
    pthread_t *id = NULL;
    int ret = -1;
    if(argc == 3){
        max_thread_cnt = atoi(argv[1]);
        max_log_cnt = atoi(argv[2]);
    }else{
        max_thread_cnt = 1;
        max_log_cnt = 1;
    }

    if(max_thread_cnt < 0){
        exit(-1);
    }
    if(max_thread_cnt > 0){
        if(max_thread_cnt > 50) {
            max_thread_cnt = 50;
        }
        id = (pthread_t *)malloc(sizeof(pthread_t) * max_thread_cnt);
        memset(id,0,sizeof(pthread_t) * max_thread_cnt);
    }

    printf("max_thread_cnt: %d, max_log_cnt %d \n", max_thread_cnt, max_log_cnt);
    log_init("test_log",LOG_FILE,LOG_LEVEL_DEBUG,LOG_MOD_VERBOSE);


    for(i = 0; i < max_thread_cnt; i++){
        ret = pthread_create(&id[i], NULL, thread_gen_logs, &max_log_cnt);
        if(ret < 0) {
            printf("create test thread failed!!!\n");
            exit(-1);
        }
    } 

    for(i = 0; i < max_thread_cnt; i++){
        pthread_join(id[i], NULL);
    } 
    if(id)
        free(id);
#ifdef OSS_FILE
    log_file_upload(NULL, "sn123456");
#endif
    log_destroy();
    //gcov: http://www.jianshu.com/p/c69b7889e878 
    //du -b --exclude='*.INFO'
    printf("the total size of log files is : %d\n",4096 + 103+max_thread_cnt*max_log_cnt*196);
    
    return 0;
}

