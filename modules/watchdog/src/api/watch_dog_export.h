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


/*
watchdog 喂狗超时后执行的操作：
OPR_REBOOT_SYSTEM： 线程喂狗超时后，watchdog直接重启系统
OPR_RESTART_PROCESS_ONLY： 线程喂狗超时后，watchdog重新拉起超时线程所在进程
*/
typedef enum{
	OPR_REBOOT_SYSTEM = 0,
	OPR_RESTART_PROCESS_ONLY = 1,

}watchdog_timeout_opreation_et;

/*
watchdog_terminate_callback : 进程收到watchdog terminate信号的回调函数。
process_feeddog_setup注册时，必须设置该回调，实现安全退出机制
除此之外，当喂狗超时后，watchdog还会额外发送SIGTERM信号给进程，请实现SIGTERM相关的handler函数
返回值：watchdog_error_et，watchdog错误码

参数： 
threadID: 喂狗超时的线程ID，请用一段字符串区分
count：watchdog将在count 秒后，直接kill掉
args: 回调函数的参数
*/

typedef int (*watchdog_terminate_callback)(const char* threadID, int count, void * args);

/*
process_feeddog_setup : 进程初始化喂狗

返回值：watchdog_error_et，watchdog错误码
参数： process_symbol: 进程ID标示，用户定义的一段字符串，这个字符串必须是合法字符（a-z, A-Z）;
		同一个进程请使用同一个字符串，后面喂狗操作也使用该字符串。
		不同的进程应该避免使用同一个字符串。
		如果使用拉起功能请确定这个字符串和dbus service配置的接口一致，接口为：iot.gateway.watchdog##.process_symbol
		watchdog_terminate_callback ，喂狗超时回调,可以为空，如果想使用watchdog拉起异常进程的操作，请添加该回调。
		args：回调参数
*/

int process_feeddog_setup(const char* process_symbol, watchdog_terminate_callback callback, void *args);
/*
thread_feeddog : 线程喂狗函数

返回值：watchdog_error_et，watchdog错误码
参数：process_symbol：一个进程标示字符串，同一个进程请确保该字符串一致 
	threadID: 一段字符串标示线程ID，注意不要重复
	count ：喂狗时间，单位S

注意：喂狗需要注意一下几种事项：
	  1. 喂狗精度为S，所以不要产生喂狗1S的操作。最好在狗饥饿前1-2 S就开始喂狗。
	  2. 在嵌入式系统中，但CPU任务繁忙时，可能出现：喂狗线程就绪，但没有调度到
	  导致线程喂狗时间推后，喂狗超时；或者喂狗操作发出，但是watchdog线程没有被
	  调度处理喂狗操作，而误杀了正常喂狗的线程。
	  为了避免这两种情况，请在任务繁忙时尽量提前两秒喂狗。

使用该API喂狗，当喂狗超时后，watchdog将reboot system	  
*/
int thread_feeddog(const char * process_symbol,const char* threadID,unsigned int count);
/*
thread_feeddog_with_operation : 线程喂狗函数(可以选定喂狗超时后的操作)
和thread_feeddog功能类似，不同的是喂狗时可以选择喂狗超时后的操作。
目前喂狗超时后，支持两种操作：
1. reboot system
2. 重启超时的进程


返回值：watchdog_error_et，watchdog错误码
参数：
	process_symbol：一个进程标示字符串，同一个进程请确保该字符串始终一致 
	threadID: 一段字符串标示线程ID，注意不要重复
	count ：喂狗时间，单位S
	opr : 参见watchdog_timeout_opreation_et

	
注意：喂狗需要注意一下几种事项：
	  1. 喂狗精度为S，所以不要产生喂狗1S的操作。最好在狗饥饿前1-2 S就开始喂狗。
	  2. 在嵌入式系统中，但CPU任务繁忙时，可能出现：喂狗线程就绪，但没有调度到
	  导致线程喂狗时间推后，喂狗超时；或者喂狗操作发出，但是watchdog线程没有被
	  调度处理喂狗操作，而误杀了正常喂狗的线程。
	  为了避免这两种情况，请在任务繁忙时尽量提前两秒喂狗。
	  
*/

int thread_feeddog_with_operation(const char * process_symbol, const char* threadID, unsigned int count, watchdog_timeout_opreation_et opr);

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


/*
process_feeddog_exit : 进程退出喂狗机制，释放喂狗相关资源。
注意：该函数不会给watchdog发射任何喂狗消息，只是单纯释放进程喂狗相关资源。

返回值：watchdog_error_et，watchdog错误码
*/

int process_feeddog_exit();

/*
get_project_root: 获取当前程序文件的绝对路径。
例如： 根目录为/home/lora/porject/
/project下有bins和configs两个文件分别保存进程执行文件和配置文件。

bins下有moduleA进程
执行moduleA一般如下：
cd /home/lora/project/bins
./moduleA
moduleA代码里有读取../configs/moduleA.config文件处理。
该函数可以帮助../configs/moduleA.config转换为绝对路径。
防止重新拉起进程时（执行目录改变了），无法获取原来相对路径的问题

参数 real_dir: 计算出的绝对路径
参数 offset_to_exec：相对进程执行目录的路径

返回值：0 成功 
		-1失败

*/
int get_realpath_by_exec_dir(char* real_dir, const char* offset_to_exec);




#endif
