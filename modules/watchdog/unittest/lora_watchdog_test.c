/*
和璞
2018.05.23
*/
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#if defined(ENABLE_REMOTE_LOG)
#include "log.h"
#endif

#ifdef SIMPLE_API
#include "watch_dog_simple_export.h"
#else
#include "watch_dog_export.h"
#endif

#define WATCHDOG_UNITTEST_TAG               "LORA_WATCHDOG-UNITTEST"
#define MAX_SLEEP_TIME 40;

int g_normal_num = 0;
int g_abnormal_num = 0;
int g_type = 0;
const char * processID[4]={

"watchdog",
PKTFWD_SYMBOL,
MQTT_SYMBOL,
MONITOR_SYMBOL
};

int lora_watchdog_unittest_exit = 0;

//ptread_t normal;
static inline void print_help_string(char *name)
{
    fprintf(stderr, "Usage:  %s [-p] process ID(1-3), [-d] normal thread num, [-s] abnormal thread normal, ",name);
    fprintf(stderr, "example: %s -p 1 -d 10 -s 10\n",name);
    exit(0);
}


void unittest_signal_handler(int sig)
{
    if (strsignal(sig)) {
#if defined(ENABLE_REMOTE_LOG)
        log_e(processID[g_type], " Caught linux SIGNAL: %s, I'm Dying!! ( ´•̥̥̥ω•̥̥̥` )\r\n", strsignal(sig));
#else
        printf("%s Caught linux SIGNAL: %s, I'm Dying!! ( ´•̥̥̥ω•̥̥̥` )\r\n", processID[g_type], strsignal(sig));

#endif		
		lora_watchdog_unittest_exit = 1;
	}
}
void show_help(int argc, char **argv)
{
    int opt = 0;
    static char buf[1024] = {0};
    if(argc < 5){
        print_help_string(argv[0]); 
    }
    while ((opt = getopt(argc, argv, "p:d:s:")) != -1) {
        switch (opt) {
			//log_i(WATCHDOG_UNITTEST_TAG, "opt value %c!\n\r",opt);
            case 'p':
                g_type = atoi(optarg);
				if(g_type > 3 || g_type == 0)
				{
					print_help_string(argv[0]); 
				}
				break;
            case 'd':
                g_normal_num = atoi(optarg);
				
                break;
            case 's':
                g_abnormal_num = atoi(optarg);
				break;
			
            case 'h':	
            default: 
            print_help_string(argv[0]); 
        }
    }

    if(g_normal_num <= 0 || g_abnormal_num < 0){
        print_help_string(argv[0]); 
    }
	return;
}


int terminate_callback(const char* threadID, int count, void * args)
{
#if defined(ENABLE_REMOTE_LOG)
	log_e(processID[g_type], " Caught watchdog ternimate signal: cause by %s, will be killed in %dS\r\n",threadID, count);
#else
	printf("%s Caught watchdog ternimate signal: cause by %s, will be killed in %dS\r\n", processID[g_type], threadID, count);
#endif	
	lora_watchdog_unittest_exit = 1;
	return 0;
}

int setup_random_seed()
{
	static int initialized;
	if (!initialized) 
	{
		int fd;
		int ret = -1;
		unsigned long seed;
		fd = open("/dev/urandom", 0);
		if (fd < 0 || read(fd, &seed, sizeof(seed)) != sizeof(seed))
		{
#if defined(ENABLE_REMOTE_LOG)			
			log_e(processID[g_type], "Could not load seed from /dev/urandom: %s",strerror(errno));
#else
			printf("%s Could not load seed from /dev/urandom: %s", processID[g_type], strerror(errno));

#endif			
			seed=time(0);
		}
		if (fd >= 0) 
			close(fd);
		srand(seed);
		initialized++;
	}
	return 0;
}

typedef struct{
	int is_normal;
	const char * thread_id;
	//int sleep_max;
}test_thread_parms_st;

void * test_thread_func(void * args)
{
	int sleep_count;
	int ret = -1;
	if(!args)
		return NULL;
	test_thread_parms_st * params = (test_thread_parms_st * )args;
	while(!lora_watchdog_unittest_exit)
	{
		sleep_count = rand() % MAX_SLEEP_TIME;
		if(sleep_count == 0 )
			continue;
#ifdef 	SIMPLE_API
		ret = thread_feeddog(processID[g_type], params->thread_id, sleep_count);
#else
		ret = thread_feeddog_with_operation(processID[g_type], params->thread_id, sleep_count, OPR_RESTART_PROCESS_ONLY);
#endif
		if(ret != WATCHDOG_SUCCESS)
		{
#if defined(ENABLE_REMOTE_LOG)				
			log_e(processID[g_type],"thread %s feed dog failed! ret : %d!\n",params->thread_id, ret );
#else
			printf("%s thread %s feed dog failed! ret : %d!\n", processID[g_type], params->thread_id, ret );
#endif			
			break;
		}
#if defined(ENABLE_REMOTE_LOG)			
		log_d(processID[g_type], "thread %s feed dog %d S!!\n\r", params->thread_id, sleep_count);
#else
		printf("%s thread %s feed dog %d S!!\n\r", processID[g_type], params->thread_id, sleep_count);

#endif
		if(params->is_normal)
			usleep((sleep_count - 1)*1000000);
		else
			usleep(2000000);
		
		continue;
	
			
	}
	if(params->thread_id)
		free((void*)params->thread_id);
	free(args);
	return NULL;
}


int main(int argc, char** argv)
{
    struct sigaction sig_sigchld;
    memset(&sig_sigchld, 0, sizeof(struct sigaction));
    sigemptyset(&sig_sigchld.sa_mask);
    sig_sigchld.sa_handler = unittest_signal_handler;
    sigaction(SIGTERM, &sig_sigchld, NULL);
    int ret = -1; 
	int i = 0;
	char tmp[128];
	pthread_t * p_normal;
	pthread_t * p_abnormal;
	char proj_root_path[FILENAME_MAX + 1] = { 0 };

	show_help(argc, argv);

	sprintf(tmp, "./lora_watchdog_%s", processID[g_type]);
#ifndef SIMPLE_API
	get_realpath_by_exec_dir(proj_root_path, tmp);
#if defined(ENABLE_REMOTE_LOG)
    ret = log_init(proj_root_path, LOG_FILE, LOG_LEVEL_WARN, LOG_MOD_VERBOSE);
#endif
#else
#if defined(ENABLE_REMOTE_LOG)	
	ret = log_init(tmp, LOG_FILE, LOG_LEVEL_WARN, LOG_MOD_VERBOSE);
#endif	
#endif

	if(ret < 0)
    {
        printf("_watchdong_unittest : log init error!!!\n");
    }

#if defined(ENABLE_REMOTE_LOG)		
    log_i(processID[g_type], "test run as %s !!! normal thread num: %d, abnormal thread num: %d\n",
                   processID[g_type], g_normal_num,g_abnormal_num);
#else
    printf("test run as %s !!! normal thread num: %d, abnormal thread num: %d\n",
                   processID[g_type], g_normal_num,g_abnormal_num);
#endif				   
#ifndef 	SIMPLE_API
	ret = process_feeddog_setup(processID[g_type], terminate_callback, NULL);
	if(ret != WATCHDOG_SUCCESS)
	{
#if defined(ENABLE_REMOTE_LOG)			
		log_e(processID[g_type], "process_feeddog_setup error : %d!\n\r",ret);
#else
		printf( "%s process_feeddog_setup error : %d!\n\r", processID[g_type], ret);
#endif		
		return 1;
	}
#endif
	setup_random_seed();

	p_normal = malloc(sizeof(pthread_t)*g_normal_num);
	
	for(i = 0; i < g_normal_num; i++ )
	{
		test_thread_parms_st * args = malloc(sizeof(test_thread_parms_st));
		args->is_normal = 1;
		sprintf(tmp, "normal_thread%d", i);
		args->thread_id = strdup(tmp);	
		if (0 != pthread_create(&p_normal[i], NULL, test_thread_func, args))
		{
#if defined(ENABLE_REMOTE_LOG)				
			log_e(processID[g_type],"pthread create %s failed!!!\n\r", args->thread_id);
#else
			printf(" %s pthread create %s failed!!!\n\r", processID[g_type], args->thread_id);
#endif			
#ifndef 	SIMPLE_API

			process_feeddog_exit();
#endif
			exit(1);
		}
	}
	p_abnormal = malloc(sizeof(pthread_t)*g_abnormal_num);

	for(i = 0; i < g_abnormal_num; i++ )
	{
		test_thread_parms_st * args = malloc(sizeof(test_thread_parms_st));
		args->is_normal = 0;
		sprintf(tmp, "abnormal_thread%d", i);
		args->thread_id = strdup(tmp);	
		if (0 != pthread_create(&p_abnormal[i], NULL, test_thread_func, args))
		{
#if defined(ENABLE_REMOTE_LOG)			
			log_e(processID[g_type],"pthread create %s failed!!!\n\r", args->thread_id);
#else
			printf(" %s pthread create %s failed!!!\n\r", processID[g_type], args->thread_id);
#endif
#ifndef 	SIMPLE_API
			process_feeddog_exit(g_type);
#endif
			exit(1);
		}
	}

	while(!lora_watchdog_unittest_exit)
	{
		ret = thread_feeddog(processID[g_type], "main_thread", 5);
		if(ret != WATCHDOG_SUCCESS)
		{
#if defined(ENABLE_REMOTE_LOG)	
			log_e(processID[g_type],"main thread feed dog failed!!!\n\r");
#else
			printf("%s main thread feed dog failed!!!\n\r", processID[g_type]);
#endif			
			lora_watchdog_unittest_exit = 1;
		}
		usleep(4000000);
		ret = thread_cancel_feeddog(processID[g_type], "main_thread");
		if(ret != WATCHDOG_SUCCESS)
		{
#if defined(ENABLE_REMOTE_LOG)			
			log_e(processID[g_type],"main cancel thread feed dog failed!!!\n\r");
#else
			printf("%s main cancel thread feed dog failed!!!\n\r" ,processID[g_type]);
#endif			
			lora_watchdog_unittest_exit = 1;
		}
		sleep(10);
	}

	for(i = 0; i < g_normal_num; i++ )
	{
		pthread_join(p_normal[i], NULL);
	}
	for(i = 0; i < g_abnormal_num; i++ )
	{
		pthread_join(p_abnormal[i], NULL);
	}
	free(p_normal);
	free(p_abnormal);
#ifndef 	SIMPLE_API
	process_feeddog_exit();
#endif	
	sleep(10);
	return 0;
}


