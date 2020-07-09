/*
 * Copyright (c) 2014-2016 Alibaba Group. All rights reserved.
 * License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <netdb.h>
#include <sys/socket.h>	     /* for AF_INET */
#include <time.h>
#include "monitor.h"

#define PING_HOST_ADDR "www.aliyun.com"
#define PING_CNT 3
#define PING_RECV_TIMEOUT 2

#if defined(MON_EXT_PING)

static int mon_bh_exe_cmd(const char *cmd, char *result, int max_len)
{
    FILE *ptr;

    if ((ptr = popen(cmd, "r")) != NULL) {
        char buf[512];
        int total_sz = 0;

        while (fgets(buf, sizeof(buf), ptr) != NULL) {

            total_sz += strlen(buf);

            if (total_sz >= max_len) {
                break;
            }

            strncat(result, buf, strlen(buf));
        }

        pclose(ptr);
        ptr = NULL;
    } else {
        log_err("popen %s error", cmd);
        return -1;
    }

    return 0;
}

#define RTT_PREFIX "rtt min/avg/max/mdev = "
static int mon_bh_get_avg_rtt(char *result, double *avg)
{
    char *p;
    double min;
    double max;
    double mdev;

    p = strstr(result, RTT_PREFIX);

    if (p == NULL) {
        log_err("strstr fail!");
        return -1;
    }

    if (sscanf(p + strlen(RTT_PREFIX), "%lf/%lf/%lf/%lf ms", &min, avg, &max, &mdev) < 4) {
        log_err("sscanf fail!");
        return -1;
    }

    return 0;
}

static int mon_bh_get_ping(mon_cb_param_t *param)
{
    int ret;
    char cmd[64];
    double avg;

    char result[1024];

    memset(result, '\0', sizeof(result));

    snprintf(cmd, sizeof(cmd), "/bin/ping -c %d -W %d -i 0.2 %s",
             PING_CNT, PING_RECV_TIMEOUT, PING_HOST_ADDR);
    ret = mon_bh_exe_cmd(cmd, result, sizeof(result));

    if (ret != 0) {
        log_err("fail!");
        return -1;
    }

    ret = mon_bh_get_avg_rtt(result, &avg);

    if (ret != 0) {
        log_info("ping avg rtt = NoN");
    } else {
        param->mon_sys.avg_rtt = avg;
        log_info("ping avg rtt = %lf ms", avg);
    }

    return 0;
}

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>

#define ICMP_DATA_LEN (56)
#define ICMP_HEAD_LEN (8)
#define ICMP_LEN  (ICMP_DATA_LEN + ICMP_HEAD_LEN)

#define SEND_BUFFER_SIZE 128
#define RECV_BUFFER_SIZE 128

static double g_mon_bh_min_rtt = 0.0;
static double g_mon_bh_max_rtt = 0.0;
static double g_mon_bh_avg_rtt = 0.0;

static char g_mon_bh_snd_buf[SEND_BUFFER_SIZE];
static char g_mon_bh_rcv_buf[RECV_BUFFER_SIZE];

static int mon_bh_icmp_unpack(struct timeval *rcv_time);

static sigjmp_buf jmpbuf;
static void alarm_func(int sig_no)
{
    siglongjmp(jmpbuf, 1);
}

struct hostent *gethostbyname_timeout(const char *hostname, int timeout)
{
    struct hostent *ht = NULL;

    signal(SIGALRM, alarm_func);

    if(sigsetjmp(jmpbuf, 1) != 0)
    {
        alarm(0);
        signal(SIGALRM, SIG_IGN);
        return NULL;
    }

    alarm(timeout);
    ht = gethostbyname2(hostname, AF_INET);
    signal(SIGALRM, SIG_IGN);

    return ht;
}

static uint16_t mon_bh_cal_cksum(struct icmp *picmp, int len)
{
    uint16_t *data = (uint16_t *)picmp;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    if (1 == len) {
        uint16_t tmp = *data;
        tmp &= 0xff00;
        sum += tmp;
    }

    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0x0000ffff);
    }

    sum = ~sum;

    return sum;
}

static int mon_bh_icmp_pack(uint16_t seq)
{
    int ret;
    struct icmp *picmp;
    struct timeval *cur_time;

    picmp = (struct icmp *)g_mon_bh_snd_buf;

    picmp->icmp_type = ICMP_ECHO;
    picmp->icmp_code = 0;
    picmp->icmp_cksum = 0;
    picmp->icmp_seq = seq;
    picmp->icmp_id = getpid();

    cur_time = (struct timeval *)picmp->icmp_data;
    ret = gettimeofday(cur_time, NULL);

    if (ret != 0) {
        perror("gettimeofday");
        return -1;
    }

    picmp->icmp_cksum = mon_bh_cal_cksum(picmp, ICMP_LEN);
    return 0;
}

static int mon_bh_send_packet(int fd, struct sockaddr_in *dest_addr, int snd_cnt)
{
    int ret;

    ret = mon_bh_icmp_pack(snd_cnt);

    if (ret != 0) {
        log_err("fail!");
        return -1;
    }

    if (sendto(fd, g_mon_bh_snd_buf, ICMP_LEN, 0,
               (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("sendto");
        return -1;
    }

    return 0;
}

static int mon_bh_recv_packet(int fd, struct sockaddr_in *dest_addr, int *rcv_cnt)
{
    int ret = 0;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct timeval rcv_time;

    if ((ret = recvfrom(fd, g_mon_bh_rcv_buf, RECV_BUFFER_SIZE,
                        0, (struct sockaddr *)dest_addr, &addrlen)) < 0) {
        perror("recvfrom");
        return -1;
    }

    gettimeofday(&rcv_time, NULL);

    ret = mon_bh_icmp_unpack(&rcv_time);

    if (ret == -1) {
        log_err("fail!");
        return -1;
    } else if (ret == 1) {
        return 1;
    } else {
        (*rcv_cnt)++;
        return 0;
    }
}

static double mon_bh_icmp_get_rtt(struct timeval *rcv_time, struct timeval *snd_time)
{
    struct timeval sub = *rcv_time;

    if ((sub.tv_usec -= snd_time->tv_usec) < 0) {
        --(sub.tv_sec);
        sub.tv_usec += 1000000;
    }

    sub.tv_sec -= snd_time->tv_sec;

    /* convert to ms */
    return sub.tv_sec * 1000.0 + sub.tv_usec / 1000.0;
}

static int mon_bh_icmp_unpack(struct timeval *rcv_time)
{
    struct ip *ip = (struct ip *)g_mon_bh_rcv_buf;
    struct icmp *picmp;
    int ip_head_len;

    ip_head_len = ip->ip_hl << 2;
    picmp = (struct icmp *)(g_mon_bh_rcv_buf + ip_head_len);

    if ((picmp->icmp_type == ICMP_ECHOREPLY) && picmp->icmp_id == getpid()) {
        double rtt;
        struct timeval *snd_time = (struct timeval *)picmp->icmp_data;
        rtt = mon_bh_icmp_get_rtt(rcv_time, snd_time);

        log_dbg("%u bytes from %s: icmp_seq=%u ttl=%u time=%.1f ms",
                ntohs(ip->ip_len) - ip_head_len,
                inet_ntoa(ip->ip_src),
                picmp->icmp_seq,
                ip->ip_ttl,
                rtt);

        if (rtt < g_mon_bh_min_rtt || 0 == g_mon_bh_min_rtt) {
            g_mon_bh_min_rtt = rtt;
        }

        if (rtt > g_mon_bh_max_rtt) {
            g_mon_bh_max_rtt = rtt;
        }

        g_mon_bh_avg_rtt += rtt;

        return 0;
    } else if ((picmp->icmp_type == ICMP_ECHO) && picmp->icmp_id == getpid()) {
        /* loopback dev will recv ori packet at first */
        return 1;
    } else {
        log_err("icmp_type = %d icmp_id = %d!", picmp->icmp_type, picmp->icmp_id);
        return -1;
    }
}

static void mon_bh_print_stat(int snd_cnt, int rcv_cnt)
{
    if (snd_cnt == 0) {
        log_err("send count = 0");
        return;
    }

    if (rcv_cnt == 0) {
        log_err("recv count = 0");
        return;
    }

    g_mon_bh_avg_rtt /= rcv_cnt;

    log_dbg("%d packets transmitted, %d received, %d%% packet loss", snd_cnt,
            rcv_cnt, (snd_cnt - rcv_cnt) / snd_cnt * 100);
    log_dbg("rtt min/avg/max = %.3f/%.3f/%.3f ms",
            g_mon_bh_min_rtt, g_mon_bh_avg_rtt, g_mon_bh_max_rtt);

}

static int mon_bh_do_ping(double *avg)
{
    int fd;
    int ret = 0;
    int snd_cnt = 0;
    int rcv_cnt = 0;
    struct timeval timeout;

    in_addr_t inaddr;
    struct sockaddr_in dest_addr;

    g_mon_bh_min_rtt = 0;
    g_mon_bh_max_rtt = 0;
    g_mon_bh_avg_rtt = 0;

    if ((fd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket");
        return -1;
    }

    timeout.tv_sec = PING_RECV_TIMEOUT;
    timeout.tv_usec = 0;

    ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (ret != 0) {
        close(fd);
        perror("setsockopt");
        return -1;
    }

    char ping_addr[32] = {'\0'};
    struct in_addr inp;

    if (inet_aton(PING_HOST_ADDR, &inp) == 1) {
        strncpy(ping_addr, PING_HOST_ADDR, 31);
    } else {
        struct hostent *ht = NULL;
        ht = gethostbyname_timeout(PING_HOST_ADDR, 5);

        if (!ht) {
            log_err("fail to gethostbyname2 %s", PING_HOST_ADDR);
            close(fd);
            return -1;
        }

        memcpy(&inp.s_addr, ht->h_addr, 4);
        strncpy(ping_addr, inet_ntoa(inp), 31);
    }

    inaddr = inet_addr(ping_addr);

    if (inaddr == INADDR_NONE) {
        close(fd);
        log_err("fail!");
        return -1;
    }

    log_dbg("ping %s", ping_addr);

    memset(&dest_addr, '\0', sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    memcpy(&dest_addr.sin_addr, &inaddr, sizeof(struct in_addr));

    while (snd_cnt < PING_CNT) {

        ret = mon_bh_send_packet(fd, &dest_addr, snd_cnt);

        if (ret != 0) {
            close(fd);
            log_err("fail!");
            return -1;
        }

        ret = mon_bh_recv_packet(fd, &dest_addr, &rcv_cnt);

        if (ret == -1) {
            log_err("fail!");
            break;
        } else if (ret == 1) {
            ret = mon_bh_recv_packet(fd, &dest_addr, &rcv_cnt);

            if (ret != 0) {
                break;
            }
        }

        struct timespec ts;

        ts.tv_sec = 0;

        ts.tv_nsec = 200 * 1000 * 1000;

        ret = nanosleep(&ts, NULL);

        if (ret == -1) {
            perror("nanosleep");
        }

        snd_cnt++;
    }

    mon_bh_print_stat(snd_cnt, rcv_cnt);
    *avg = g_mon_bh_avg_rtt;

    close(fd);
    return ret;
}

static int mon_bh_get_ping(mon_cb_param_t *param)
{
    int ret;
    double avg;
    ret = mon_bh_do_ping(&avg);

    if (ret != 0) {
        log_info("ping avg rtt = NoN");
    } else {
        param->mon_sys.avg_rtt = avg;
        log_info("ping avg rtt = %lf ms", avg);
    }

    return 0;
}

#endif

static int mon_backhaul_ping_init(void)
{
    log_dbg("init start");
    mon_reg_cb(MON_BH_PING, mon_bh_get_ping);
    return 0;
}

static int (*_mon_backhaul_ping_init)(void) __init_call = mon_backhaul_ping_init;
