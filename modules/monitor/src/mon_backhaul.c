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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>
#include <ctype.h>
#include "monitor.h"

#define MAX_DEV_CNT (10)

typedef struct {
    unsigned long long rx_packets;	/* total packets received       */
    unsigned long long tx_packets;	/* total packets transmitted    */
    unsigned long long rx_bytes;	/* total bytes received         */
    unsigned long long tx_bytes;	/* total bytes transmitted      */
    unsigned long rx_errors;	/* bad packets received         */
    unsigned long tx_errors;	/* packet transmit problems     */
    unsigned long rx_dropped;	/* no space in linux buffers    */
    unsigned long tx_dropped;	/* no space available in linux  */
    unsigned long rx_multicast;	/* multicast packets received   */
    unsigned long rx_compressed;
    unsigned long tx_compressed;
    unsigned long collisions;

    /* detailed rx_errors: */
    unsigned long rx_length_errors;
    unsigned long rx_over_errors;	/* receiver ring buff overflow  */
    unsigned long rx_crc_errors;	/* recved pkt with crc error    */
    unsigned long rx_frame_errors;	/* recv'd frame alignment error */
    unsigned long rx_fifo_errors;	/* recv'r fifo overrun          */
    unsigned long rx_missed_errors;	/* receiver missed packet     */
    /* detailed tx_errors */
    unsigned long tx_aborted_errors;
    unsigned long tx_carrier_errors;
    unsigned long tx_fifo_errors;
    unsigned long tx_heartbeat_errors;
    unsigned long tx_window_errors;
} user_net_device_stats_t;

static int g_mon_bh_cur_cnt = 0;
static mon_bh_dev_t g_mon_bh_dev[MAX_BH_DEV_CNT];

static int mon_bh_filter_type(const char *name, int *type)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        perror("socket");
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);

    *type = ifr.ifr_hwaddr.sa_family;

    if (*type == ARPHRD_PPP || *type == ARPHRD_ETHER) {
        return 0;
    } else {
        return -1;
    }
}

static int mon_bh_get_avail_ifname(void)
{
    int i;
    int ret;
    int fd;
    int type;
    char *s;
    int idx = 0;
    struct ifreq ifr[MAX_DEV_CNT];
    struct ifconf ifc;

    memset(&ifc, '\0', sizeof(ifc));

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    ifc.ifc_len = MAX_DEV_CNT * sizeof(struct ifreq);
    ifc.ifc_buf = (char *)ifr;

    ioctl(fd, SIOCGIFCONF, &ifc);

    for (i = 0; i < (ifc.ifc_len / sizeof(struct ifreq)); i++) {
        if (ifr[i].ifr_flags == AF_INET) {
            log_info("if name = %s", ifr[i].ifr_name);
            ret = mon_bh_filter_type(ifr[i].ifr_name, &type);

            if (ret != 0) {
                log_dbg("if name = %s type = %d is not ether or ppp", ifr[i].ifr_name, type);
            } else {
                if (idx > MAX_BH_DEV_CNT - 1) {
                    log_err("available if more than %d", MAX_BH_DEV_CNT);
                    break;
                }

                if (type == ARPHRD_PPP) {
                    g_mon_bh_dev[idx].type = MON_TYPE_4G;
                    strncpy(g_mon_bh_dev[idx].type_name, "4G", MAX_BH_TYPE_LEN - 1);
                } else {
                    g_mon_bh_dev[idx].type = MON_TYPE_ETHERNET;
                    strncpy(g_mon_bh_dev[idx].type_name, "ETHERNET", MAX_BH_TYPE_LEN - 1);
                }

                s = inet_ntoa(((struct sockaddr_in *) & (ifr[i].ifr_addr))->sin_addr);
                strncpy(g_mon_bh_dev[idx].ipaddr, s, INET_ADDRSTRLEN - 1);
                strncpy(g_mon_bh_dev[idx].name, ifr[i].ifr_name, IFNAMSIZ - 1);
                idx++;
            }
        } else {
            log_info("only IPv4 support!");
        }
    }

    close(fd);

    return 0;
}

static int mon_bh_get_dev_fields(char *bp, user_net_device_stats_t *stats, int proc_ver)
{
    switch (proc_ver) {
        case 3:
            sscanf(bp,
                   "%Lu %Lu %lu %lu %lu %lu %lu %lu %Lu %Lu %lu %lu %lu %lu %lu %lu",
                   &stats->rx_bytes,
                   &stats->rx_packets,
                   &stats->rx_errors,
                   &stats->rx_dropped,
                   &stats->rx_fifo_errors,
                   &stats->rx_frame_errors,
                   &stats->rx_compressed,
                   &stats->rx_multicast,

                   &stats->tx_bytes,
                   &stats->tx_packets,
                   &stats->tx_errors,
                   &stats->tx_dropped,
                   &stats->tx_fifo_errors,
                   &stats->collisions,
                   &stats->tx_carrier_errors,
                   &stats->tx_compressed);
            break;

        case 2:
            sscanf(bp, "%Lu %Lu %lu %lu %lu %lu %Lu %Lu %lu %lu %lu %lu %lu",
                   &stats->rx_bytes,
                   &stats->rx_packets,
                   &stats->rx_errors,
                   &stats->rx_dropped,
                   &stats->rx_fifo_errors,
                   &stats->rx_frame_errors,

                   &stats->tx_bytes,
                   &stats->tx_packets,
                   &stats->tx_errors,
                   &stats->tx_dropped,
                   &stats->tx_fifo_errors,
                   &stats->collisions,
                   &stats->tx_carrier_errors);
            stats->rx_multicast = 0;
            break;

        case 1:
            sscanf(bp, "%Lu %lu %lu %lu %lu %Lu %lu %lu %lu %lu %lu",
                   &stats->rx_packets,
                   &stats->rx_errors,
                   &stats->rx_dropped,
                   &stats->rx_fifo_errors,
                   &stats->rx_frame_errors,

                   &stats->tx_packets,
                   &stats->tx_errors,
                   &stats->tx_dropped,
                   &stats->tx_fifo_errors,
                   &stats->collisions,
                   &stats->tx_carrier_errors);
            stats->rx_bytes = 0;
            stats->tx_bytes = 0;
            stats->rx_multicast = 0;
            break;
    }

    return 0;
}

static int mon_bh_get_proc_ver(char *buf)
{
    if (strstr(buf, "compressed")) {
        return 3;
    }

    if (strstr(buf, "bytes")) {
        return 2;
    }

    return 1;
}


static char *mon_bh_get_name(char *name, char *p)
{
    while (isspace(*p)) {
        p++;
    }

    while (*p) {
        if (isspace(*p)) {
            break;
        }

        if (*p == ':') {	/* could be an alias */
            char *dot = p++;

            while (*p && isdigit(*p)) {
                p++;
            }

            if (*p == ':') {
                /* Yes it is, backup and copy it. */
                p = dot;
                *name++ = *p++;

                while (*p && isdigit(*p)) {
                    *name++ = *p++;
                }
            } else {
                /* No, it isn't */
                p = dot;
            }

            p++;
            break;
        }

        *name++ = *p++;
    }

    *name++ = '\0';
    return p;
}

static int mon_bh_fill_type(int type)
{

    if (type == MON_TYPE_ETHERNET || type == MON_TYPE_4G) {
        return 1;
    } else {
        return 0;
    }
}

#define PROCNET_DEV_FILE  "/proc/net/dev"
static int mon_bh_fill_traffic(void)
{
    int i;
    int ret;
    FILE *fp;
    char buf[512];
    int proc_ver;
    user_net_device_stats_t stats;

    fp = fopen(PROCNET_DEV_FILE, "r");
    if (NULL == fp) {
        log_err("fopen %s error", PROCNET_DEV_FILE);
        return -1;
    }

    fgets(buf, sizeof(buf), fp); /* eat line */
    fgets(buf, sizeof(buf), fp);

    proc_ver = mon_bh_get_proc_ver(buf);

    while (fgets(buf, sizeof(buf), fp)) {
        char *s, name[IFNAMSIZ];
        s = mon_bh_get_name(name, buf);

        for (i = 0; i < MAX_BH_DEV_CNT; i++) {
            if (mon_bh_fill_type(g_mon_bh_dev[i].type)) {
                if (strncmp(name, g_mon_bh_dev[i].name, strlen(name)) == 0) {
                    break;
                }
            }
        }

        if (i == MAX_BH_DEV_CNT) {
            continue;
        }

        log_dbg("%s interface name is %s", PROCNET_DEV_FILE, name);
        mon_bh_get_dev_fields(s, &stats, proc_ver);
        log_dbg("%s tx_packets=%lld, tx_bytes=%lld, rx_pakcets=%lld, rx_bytes=%lld",
                name, stats.tx_packets, stats.tx_bytes, stats.rx_packets,
                stats.rx_bytes);

        g_mon_bh_dev[i].tx_packets = stats.tx_packets;
        g_mon_bh_dev[i].tx_bytes = stats.tx_bytes;
        g_mon_bh_dev[i].rx_packets = stats.rx_packets;
        g_mon_bh_dev[i].rx_bytes = stats.rx_bytes;

        double uptime;
        ret = mon_util_get_uptime(&uptime);

        if (ret != 0) {
            log_err("fail!");
            break;
        }

        g_mon_bh_dev[i].tx_bitrate = g_mon_bh_dev[i].tx_bytes * 8 / uptime;
        g_mon_bh_dev[i].rx_bitrate = g_mon_bh_dev[i].rx_bytes * 8 / uptime;
    }

    fclose(fp);

    return 0;
}

static int mon_bh_update(void)
{
    if (g_mon_bh_cur_cnt < mon_get_cnt()) {

        int ret;

        memset(g_mon_bh_dev, '\0', sizeof(g_mon_bh_dev));
        ret = mon_bh_get_avail_ifname();

        if (ret != 0) {
            log_err("fail!");
            return -1;
        }

        ret = mon_bh_fill_traffic();

        if (ret != 0) {
            log_err("fail!");
            return -1;
        }

        g_mon_bh_cur_cnt++;
    }

    return 0;
}

static int mon_bh_get_iftype(mon_cb_param_t *param)
{
    int i;

    if (mon_bh_update() != 0) {
        log_err("fail!");
        return -1;
    }

    for (i = 0; i < MAX_BH_DEV_CNT; i++) {
        if (mon_bh_fill_type(g_mon_bh_dev[i].type)) {
            param->mon_bh_dev[i].type = g_mon_bh_dev[i].type;
            strncpy(param->mon_bh_dev[i].name, g_mon_bh_dev[i].name, IFNAMSIZ - 1);
            strncpy(param->mon_bh_dev[i].type_name, g_mon_bh_dev[i].type_name, MAX_BH_TYPE_LEN - 1);
            log_info("dev %s is %s network", g_mon_bh_dev[i].name, g_mon_bh_dev[i].type_name);
        }
    }

    return 0;
}

static int mon_bh_get_traffic(mon_cb_param_t *param)
{
    int i;

    if (mon_bh_update() != 0) {
        log_err("fail!");
        return -1;
    }

    for (i = 0; i < MAX_BH_DEV_CNT; i++) {
        if (mon_bh_fill_type(g_mon_bh_dev[i].type)) {
            log_info("%s tx_packets=%lld tx_bytes=%lld rx_packets=%lld rx_bytes=%lld",
                     g_mon_bh_dev[i].name, g_mon_bh_dev[i].tx_packets,
                     g_mon_bh_dev[i].tx_bytes, g_mon_bh_dev[i].rx_packets,
                     g_mon_bh_dev[i].rx_bytes);
            param->mon_bh_dev[i].tx_packets = g_mon_bh_dev[i].tx_packets;
            param->mon_bh_dev[i].rx_packets = g_mon_bh_dev[i].rx_packets;
            param->mon_bh_dev[i].tx_bytes = g_mon_bh_dev[i].tx_bytes;
            param->mon_bh_dev[i].rx_bytes = g_mon_bh_dev[i].rx_bytes;
        }
    }

    return 0;
}

static int mon_bh_get_ip(mon_cb_param_t *param)
{
    int i;

    if (mon_bh_update() != 0) {
        log_err("fail!");
        return -1;
    }

    for (i = 0; i < MAX_BH_DEV_CNT; i++) {
        if (mon_bh_fill_type(g_mon_bh_dev[i].type)) {
            strncpy(param->mon_bh_dev[i].ipaddr, g_mon_bh_dev[i].ipaddr, INET_ADDRSTRLEN - 1);
            log_info("dev %s ip = %s", g_mon_bh_dev[i].name, g_mon_bh_dev[i].ipaddr);
        }
    }

    return 0;
}

static int mon_bh_get_bitrate(mon_cb_param_t *param)
{
    int i;

    if (mon_bh_update() != 0) {
        log_err("fail!");
        return -1;
    }

    for (i = 0; i < MAX_BH_DEV_CNT; i++) {
        if (mon_bh_fill_type(g_mon_bh_dev[i].type)) {
            log_info("%s tx_bitrate=%lf rx_bitrate=%lf",
                     g_mon_bh_dev[i].name, g_mon_bh_dev[i].tx_bitrate,
                     g_mon_bh_dev[i].rx_bitrate);
            param->mon_bh_dev[i].tx_bitrate = g_mon_bh_dev[i].tx_bitrate;
            param->mon_bh_dev[i].rx_bitrate = g_mon_bh_dev[i].rx_bitrate;
        }
    }

    return 0;
}

static int mon_backhaul_init(void)
{
    log_dbg("init start");
    mon_reg_cb(MON_BH_TYPE, mon_bh_get_iftype);
    mon_reg_cb(MON_BH_IP, mon_bh_get_ip);
    mon_reg_cb(MON_BH_TRAFFIC, mon_bh_get_traffic);
    mon_reg_cb(MON_BH_BITRATE, mon_bh_get_bitrate);
    return 0;
}

static int (*_mon_backhaul_init)(void) __init_call = mon_backhaul_init;
