/*
 * thread_pool.c
 *
 * 从 @秋坻 的 cmp_bus_trpool.c/h 中移植
 *
 *  Created on: 2017年11月11日
 *      Author: Zhongyang
 */

#include "thread_pool.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <assert.h>
#include "_watchdog_includes.h"
#define TP_TAG "ThreadPool"

void *_tp_thread_routine(void *arg);

static CThreadPool *_pool = NULL;

void tp_pool_init(int max_thread_num)
{
    int i = 0;
    int rc = -1;
    _pool = (CThreadPool *) malloc(sizeof(CThreadPool));
    pthread_mutex_init(&(_pool->queue_lock), NULL);
    pthread_cond_init(&(_pool->queue_ready), NULL);
    _pool->queue_head = NULL;
    _pool->max_thread_num = max_thread_num;
    _pool->cur_queue_size = 0;
    _pool->shutdown = 0;
    _pool->threadid = (pthread_t *) malloc(max_thread_num * sizeof(pthread_t));
    for (i = 0; i < max_thread_num; i++)
    {
        rc = pthread_create(&(_pool->threadid[i]), NULL, _tp_thread_routine, NULL);
        if(rc != 0) {
            log_err("thread pool init failed!!! pthread_create error!!!");
            return;
        }
    }
}

/*向线程池中加入任务*/
int tp_pool_add_worker(void *(*process)(void *arg), void *arg)
{
    /*构造一个新任务*/
    CThreadPoolWorker *newworker = (CThreadPoolWorker *) malloc(sizeof(CThreadPoolWorker));
    newworker->process = process;
    newworker->arg = arg;
    newworker->next = NULL;
    pthread_mutex_lock(&(_pool->queue_lock));
    /*将任务加入到等待队列中*/
    CThreadPoolWorker *member = _pool->queue_head;
    if (member != NULL)
    {
        while (member->next != NULL)
        {
            member = member->next;
        }
        member->next = newworker;
    }
    else
    {
        _pool->queue_head = newworker;
    }
    assert(_pool->queue_head != NULL);
    (_pool)->cur_queue_size++;
    pthread_mutex_unlock(&((_pool)->queue_lock));
    /*好了，等待队列中有任务了，唤醒一个等待线程；
     注意如果所有线程都在忙碌，这句没有任何作用*/
    pthread_cond_signal(&((_pool)->queue_ready));
    return TP_ERROR_SUCCESS;
}

/*销毁线程池，等待队列中的任务不会再被执行，但是正在运行的线程会一直
 把任务运行完后再退出*/
int tp_pool_destroy(void)
{
    int i;
    CThreadPoolWorker *head = NULL;

    if (_pool->shutdown)
    {
        return TP_ERROR_FAILED;/*防止两次调用*/
    }
    _pool->shutdown = 1;
    /*唤醒所有等待线程，线程池要销毁了*/
    pthread_cond_broadcast(&(_pool->queue_ready));
    /*阻塞等待线程退出，否则就成僵尸了*/
    for (i = 0; i < _pool->max_thread_num; i++)
    {
        pthread_join(_pool->threadid[i], NULL);
    }
    free(_pool->threadid);
    /*销毁等待队列*/
    while (_pool->queue_head != NULL)
    {
        head = _pool->queue_head;
        _pool->queue_head = _pool->queue_head->next;
        free(head);
    }
    /*条件变量和互斥量也别忘了销毁*/
    pthread_mutex_destroy(&(_pool->queue_lock));
    pthread_cond_destroy(&(_pool->queue_ready));

    free(_pool);
    /*销毁后指针置空是个好习惯*/
    _pool = NULL;
    return TP_ERROR_SUCCESS;
}

void *_tp_thread_routine(void *arg)
{
    log_info("starting thread 0x%x\r\n", pthread_self());
    while (1)
    {
        pthread_mutex_lock(&(_pool->queue_lock));
        /*如果等待队列为0并且不销毁线程池，则处于阻塞状态; 注意
         pthread_cond_wait是一个原子操作，等待前会解锁，唤醒后会加锁*/
        while (_pool->cur_queue_size == 0 && !_pool->shutdown)
        {
            /* log_debug("thread 0x%x is waiting\r\n", pthread_self()); */
            pthread_cond_wait(&(_pool->queue_ready), &(_pool->queue_lock));
        }
        /*线程池要销毁了*/
        if (_pool->shutdown)
        {
            /*遇到break,continue,return等跳转语句，千万不要忘记先解锁*/
            pthread_mutex_unlock(&(_pool->queue_lock));
            log_debug("thread 0x%x will exit\r\n", pthread_self());
            pthread_exit(NULL);
        }
        /* log_info("thread 0x%x is starting to work\r\n", pthread_self()); */
        /*assert是调试的好帮手*/
        assert(_pool->cur_queue_size != 0);
        assert(_pool->queue_head != NULL);

        /*等待队列长度减去1，并取出链表中的头元素*/
        (_pool)->cur_queue_size--;
        CThreadPoolWorker *worker = _pool->queue_head;
        _pool->queue_head = worker->next;
        pthread_mutex_unlock(&(_pool->queue_lock));
        /*调用回调函数，执行任务*/
        (*(worker->process))(worker->arg);
        free(worker);
        worker = NULL;
    }
    /*这一句应该是不可达的*/
    pthread_exit(NULL);
}

