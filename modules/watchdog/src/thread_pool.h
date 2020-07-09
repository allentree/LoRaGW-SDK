/*
 * thread_pool.h
 *
 * 从 @秋坻 的 cmp_bus_trpool.c/h 中移植
 *  Created on: 2017年11月11日
 *      Author: Zhongyang
 */

#ifndef MODULES_WATCHDOG_THREAD_POOL_THREAD_POOL_H_
#define MODULES_WATCHDOG_THREAD_POOL_THREAD_POOL_H_

#include <pthread.h>

#define TP_ERROR_SUCCESS (0)
#define TP_ERROR_FAILED (3)

/*
 *线程池里所有运行和等待的任务都是一个CThread_worker
 *由于所有任务都在链表里，所以是一个链表结构
 */
typedef struct CThreadPoolWorkerTag
{
    void *(*process)(void *arg);
    void *arg;/*回调函数的参数*/
    struct CThreadPoolWorkerTag *next;
} CThreadPoolWorker;

/*线程池结构*/
typedef struct
{
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_ready;
    /*链表结构，线程池中所有等待任务*/
    CThreadPoolWorker *queue_head;
    /*是否销毁线程池*/
    int shutdown;
    pthread_t *threadid;
    /*线程池中允许的活动线程数目*/
    int max_thread_num;
    /*当前等待队列的任务数目*/
    int cur_queue_size;
} CThreadPool;

void tp_pool_init(int max_thread_num);
int tp_pool_add_worker(void *(*process)(void *arg), void *arg);
int tp_pool_destroy(void);

#endif /* MODULES_WATCHDOG_THREAD_POOL_THREAD_POOL_H_ */
