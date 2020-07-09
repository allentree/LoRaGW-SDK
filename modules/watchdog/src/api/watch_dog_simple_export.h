#ifndef _WATCH_DOG_EXPORT_H
#define _WATCH_DOG_EXPORT_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>

/*
预定义的process symbol
可以直接添加新的process symbol，不需要重新编译libwatchdog
添加新的process请不要使用非法字符，合法字符为（a-z , A-Z）
请注意避免添加的process symbol重复
dbus总线的well-known name为:iot.gateway.watchdog+SYMBOL, 例如： iot.gateway.watchdog.pktfwd iot.gateway.watchdog.mqtt  iot.gateway.watchdog.monitor
*/
#ifndef PKTFWD_SYMBOL
#define PKTFWD_SYMBOL  "pktfwd"
#endif
#ifndef MQTT_SYMBOL
#define MQTT_SYMBOL  "mqtt"
#endif
#ifndef MONITOR_SYMBOL
#define MONITOR_SYMBOL  "monitor"
#endif
#ifndef UPDATE_SYMBOL
#define UPDATE_SYMBOL  "update"
#endif


typedef enum{
	WATCHDOG_SUCCESS = 0,
	WATCHDOG_ERROR_INVALID_PARAM = -1,
    WATCHDOG_ERROR_NO_MEM = -2,
    WATCHDOG_ERROR_BUS_INVALID = -3,
    WATCHDOG_ERROR_IO = -4,
    WATCHDOG_ERROR_INVALID_DATA = -5,
    WATCHDOG_ERROR_TIME_OUT = -6,
	WATCHDOG_ERROR_INVALID_PROCESSID = -7,
	WATCHDOG_ERROR_PROCESS_INVALID_CONFIG = -8,
	WATCHDOG_ERROR_DBUS_ALLOC = -9,
	WATCHDOG_ERROR_DBUS_SEND = -10,
}watchdog_error_et;

typedef enum{
	OPR_REBOOT_SYSTEM = 0,
	OPR_RESTART_PROCESS_ONLY = 1,

}watchdog_timeout_opreation_et;

/*
thread_feeddog : 线程喂狗函数

返回值：watchdog_error_et，watchdog错误码
参数：
	process_symbol：一个进程标示字符串，同一个进程请确保该字符串一致 
	threadID: 一段字符串标示线程ID，注意不要重复
	count ：喂狗时间，单位S

注意：喂狗需要注意一下几种事项：
	  1. 喂狗精度为S，所以不要产生喂狗1S的操作。最好在狗饥饿前1S就开始喂狗。
	  2. 在嵌入式系统中，但CPU任务繁忙时，可能出现：喂狗线程就绪，但没有调度到
	  导致线程喂狗时间推后，喂狗超时；或者喂狗操作发出，但是watchdog线程没有被
	  调度处理喂狗操作，而误杀了正常喂狗的线程。
	  为了避免这两种情况，请在任务繁忙时尽量提前两秒喂狗。

使用该API喂狗，当喂狗超时后，watchdog将reboot system	  
*/




int thread_feeddog(const char * process_symbol,const char* threadID,unsigned int count);

/*
thread_feeddog_periodically : 线程周期喂狗函数
在一个线程的执行loop中调用该函数，可以实现固定时间间隔进行一次喂狗

返回值：watchdog_error_et，watchdog错误码
参数：
	process_symbol：一个进程标示字符串，同一个进程请确保该字符串始终一致 
	threadID: 一段字符串标示线程ID，注意不要重复
	feed_interval ： 每次喂狗的间隔，单位为S
	feed_count ： 每次喂狗的时间量，单位为S
	time_keeper： 上次喂狗的时间
应用场景：
	一些线程有个执行的loop函数，需要在这个loop函数里进行喂狗，但是每次loop的执行时间太短，
	喂狗没有必要每个loop都喂狗，我们期望一个固定的时间进行一次喂狗就可以了。
调用实现参考： 
	struct timespec watchdog_time_keeper;
	clock_gettime(CLOCK_MONOTONIC, &watchdog_time_keeper);
	while(1)
	{
		//your thread process
		...

		//每10S 喂狗一次，每次喂狗20S
		thread_feeddog_periodically("your_prcess_symbol", "your_thread_id", 10, 20, &watchdog_time_keeper)
	}
note: 每次喂狗时间量必须大于喂狗间隔时间5S及以上
*/
int thread_feeddog_periodically(const char * process_symbol, const char * threadID, unsigned int feed_interval, unsigned int feed_count, void * time_keeper);


/*
thread_cancel_feeddog : 线程取消喂狗

返回值：watchdog_error_et，watchdog错误码
参数： 
	process_symbol： ：一个进程标示字符串，同一个进程请确保该字符串始终一致
	threadID: 一段字符串标示线程ID，注意不要重复

注意：如果前面以及再喂狗，在取消喂狗是同样要考虑thread_feeddog函数的注意事项。
*/


int thread_cancel_feeddog(const char * process_symbol, const char * threadID);


#endif

