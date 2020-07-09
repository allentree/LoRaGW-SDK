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

#include <sys/statvfs.h>
#include "monitor.h"

static int mon_sys_get_fs_stat(const char *path, int *percent)
{
    int ret;
    struct statvfs buf;

    fsblkcnt_t used;
    fsblkcnt_t u100;
    fsblkcnt_t nonroot_total;

    ret = statvfs(path, &buf);

    if (ret != 0) {
        perror("statvfs");
        return -1;
    }

    if (buf.f_blocks <= 0 || buf.f_bfree <= 0 || buf.f_bavail <= 0) {
        log_err("statvfs buf value error!");
        return -1;
    }

    if (buf.f_blocks < buf.f_bfree) {
        log_err("statvfs f_blocks < f_bfree error!");
        return -1;
    }

    used = buf.f_blocks - buf.f_bfree;
    u100 = used * 100;
    nonroot_total = used + buf.f_bavail;
    *percent = u100 / nonroot_total + (u100 % nonroot_total != 0);

    return ret;
}

#ifdef MONITOR_SYS_FS_EXT
extern int monitor_get_mount_point(int *cnt, void **mount_point);

static int mon_sys_get_fs(mon_cb_param_t *param)
{
    int i;
    int cnt;
    int ret;
    int pct = -1;
    void *mount_point;
    char **mount_point_p;

    ret = monitor_get_mount_point(&cnt, &mount_point);

    if (ret != 0) {
        log_err("fail to get mount point info");
        return -1;
    }

    if (cnt > MAX_FS_MOUNT_POINT_CNT) {
        log_err("mount point count > %d", MAX_FS_MOUNT_POINT_CNT);
        return -1;
    }

    mount_point_p = (char **)mount_point;

    for (i = 0; i < cnt; i++) {

        ret = mon_sys_get_fs_stat(mount_point_p[i], &pct);

        if (ret != 0) {
            log_err("fail to get fs info");
            continue;
        } else {
            strncpy(param->mon_sys.fs[i].fs_name, mount_point_p[i],
                    MAX_FS_MOUNT_POINT_LEN - 1);
            param->mon_sys.fs[i].percent = pct;
            param->mon_sys.fs_cnt++;

            log_dbg("mount point %s percent is %d", mount_point_p[i], pct);
        }

    }

    return 0;
}

#else
#define DEFAULT_MOUNT_POINT "/"

static int mon_sys_get_fs(mon_cb_param_t *param)
{
    int ret;
    int pct = -1;

    log_dbg("start to get fs info");
    ret = mon_sys_get_fs_stat(DEFAULT_MOUNT_POINT, &pct);

    if (ret != 0) {
        log_err("fail to get fs info");
        return -1;
    }

    param->mon_sys.fs_cnt = 1;
    strncpy(param->mon_sys.fs[0].fs_name, DEFAULT_MOUNT_POINT,
            MAX_FS_MOUNT_POINT_LEN - 1);
    param->mon_sys.fs[0].percent = pct;

    log_dbg("percent is %d", pct);

    return 0;
}
#endif

#define UPTIME_FILE  "/proc/uptime"

static int mon_sys_get_uptime(mon_cb_param_t *param)
{
    int ret;
    double up = 0;

    log_dbg("start to get uptime");

    ret = mon_util_get_uptime(&up);

    if (ret != 0) {
        log_err("fail!");
        return -1;
    }

    param->mon_sys.uptime = up;
    log_dbg("uptime is %f", up);

    return 0;
}

struct cpu_stat_s {
    char cpu_name[32];
    uint64_t user;
    uint64_t nice;
    uint64_t system;
    uint64_t idle;
    uint64_t iowait;
    uint64_t irq;
    uint64_t softirq;
    uint64_t steal;
};

static uint64_t pre_cpu_sum = 0;
static uint64_t pre_cpu_idle = 0;

static int get_cpu_stat(struct cpu_stat_s *cpu_stat)
{
    FILE *fp;
    char buff[512];

    fp = fopen("/proc/stat", "r");

    if (NULL == fp) {
        log_err("fopen /proc/stat file error");
        return -1;
    }

    fgets(buff, sizeof(buff), fp);
    sscanf(buff, "%s %llu %llu %llu %llu %llu %llu %llu %llu ",
           cpu_stat->cpu_name, &cpu_stat->user, &cpu_stat->nice,
           &cpu_stat->system, &cpu_stat->idle, &cpu_stat->iowait,
           &cpu_stat->irq, &cpu_stat->softirq, &cpu_stat->steal);

    fclose(fp);

    return 0;
}

static int mon_sys_get_cpu(mon_cb_param_t *param)
{
    struct cpu_stat_s cpu_stat;
    uint64_t cpu_sum = 0;
    uint64_t cpu_sum_diff = 0;
    uint64_t cpu_idle_diff = 0;
    int ret = 0;
    float cpu_ratio;

    cpu_ratio = 0.0;

    ret = get_cpu_stat(&cpu_stat);

    if (ret == 0) {
        cpu_sum = cpu_stat.user + cpu_stat.nice + cpu_stat.system +
                  cpu_stat.idle + cpu_stat.iowait + cpu_stat.irq +
                  cpu_stat.softirq + cpu_stat.steal;
        cpu_idle_diff = cpu_stat.idle - pre_cpu_idle;
        cpu_sum_diff = cpu_sum - pre_cpu_sum;

        if (cpu_sum_diff != 0) {
            cpu_ratio = (float)(cpu_sum_diff - cpu_idle_diff) /
                        (float)cpu_sum_diff;
        }

        pre_cpu_idle = cpu_stat.idle;
        pre_cpu_sum = cpu_sum;
    }

    cpu_ratio = (cpu_ratio) * 100.0;
    log_dbg("cpu_ratio: %.2f", (cpu_ratio) * 100.0);
    param->mon_sys.cpu = cpu_ratio;

    return 0;
}

static int mon_sys_get_memory(mon_cb_param_t *param)
{
    FILE *fp = NULL;
    char buff[256] = {0};
    char mem_name[32] = {0};
    uint32_t mem_total = 0;
    uint32_t mem_free  = 0;
    uint32_t mem_used  = 0;
    uint32_t mem_cached = 0;
    uint8_t get_cached_mem = 0;
    float mem_ratio = 0.0;

    fp = fopen("/proc/meminfo", "r");

    if (NULL == fp) {
        log_err("fopen /proc/meminfo file error");
        return -1;
    }

    fgets(buff, sizeof(buff), fp);
    sscanf(buff, "%s %u ", mem_name, &mem_total);

    fgets(buff, sizeof(buff), fp);
    sscanf(buff, "%s %u ", mem_name, &mem_free);

    while (fgets(buff, sizeof(buff), fp)) {

        sscanf(buff, "%s %u ", mem_name, &mem_cached);

        if (strncmp(mem_name , "Cached", strlen("Cached")) == 0) {
            get_cached_mem = 1;
            break;
        }
    }

    mem_used = mem_total - mem_free;

    if (get_cached_mem) {
        mem_used -= mem_cached;
    }

    if (mem_total != 0) {
        mem_ratio = (float)mem_used / (float)mem_total;
    }

    mem_ratio = (mem_ratio) * 100.0;
    log_dbg("mem_ratio: %.2f", (mem_ratio) * 100.0);
    param->mon_sys.memory = mem_ratio;

    fclose(fp);

    return 0;
}

#ifdef MONITOR_SYS_TEMP
#ifdef MONITOR_SYS_TEMP_EXT
extern int monitor_get_cpu_temp(double *val);

static int mon_sys_get_temp(mon_cb_param_t *param)
{
    int ret;
    double temp = 0;

    ret = monitor_get_cpu_temp(&temp);

    if (ret < 0) {
        log_err("fail to get temperature info");
        return -1;
    } else {
        param->mon_sys.temp = temp;
        log_dbg("temp is %f", temp);
        return 0;
    }
}

#else
#define TEMP_FILE "/sys/class/thermal/thermal_zone0/temp"

static int mon_sys_get_temp(mon_cb_param_t *param)
{
    FILE *tempinfo;
    char buf[32];
    double temp = 0;

    log_dbg("start to get temperature");
    tempinfo = fopen(TEMP_FILE, "r");

    if (tempinfo == NULL) {
        log_info("fail to open %s", TEMP_FILE);
        return -1;
    }

    if (fgets(buf, sizeof(buf), tempinfo) == NULL) {
        perror("fgets");
        fclose(tempinfo);
        return -1;
    }

    if (sscanf(buf, "%lf", &temp) < 1) {
        log_err("fail to sscanf");
        fclose(tempinfo);
        return -1;
    }

    temp = temp / 1000;
    param->mon_sys.temp = temp;
    log_dbg("temp is %f", temp);

    fclose(tempinfo);

    return 0;
}
#endif
#endif

#ifdef MONITOR_SYS_BAT
#ifdef MONITOR_SYS_BAT_EXT
extern int monitor_get_battery(int *val);

static int mon_sys_get_bat(mon_cb_param_t *param)
{
    int ret;
    int bat = 0;

    ret = monitor_get_battery(&bat);

    if (ret < 0) {
        log_err("fail to get power info");
        return -1;
    } else {
        param->mon_sys.power = bat;
        log_dbg("power is %d", bat);
        return 0;
    }
}
#else

#define BAT_FILE "/sys/class/power_supply/BAT0/capacity"

static int mon_sys_get_bat(mon_cb_param_t *param)
{
    FILE *batinfo;
    char buf[32];
    int bat = 0;

    log_dbg("start to get power");
    batinfo = fopen(BAT_FILE, "r");

    if (batinfo == NULL) {
        log_info("fail to open %s", BAT_FILE);
        return -1;
    }

    if (fgets(buf, sizeof(buf), batinfo) == NULL) {
        perror("fgets");
        fclose(batinfo);
        return -1;
    }

    if (sscanf(buf, "%d", &bat) < 1) {
        log_err("fail to sscanf");
        fclose(batinfo);
        return -1;
    }

    param->mon_sys.power = bat;
    log_dbg("power is %d", bat);

    fclose(batinfo);

    return 0;
}
#endif
#endif

#ifdef MONITOR_SYS_ABP_NS
static const char abp_ns_stat_key[]   = {"abp:ns:state"};
static const char abp_ns_limit_key[]  = {"abp:nodes:limit"};
static int mon_sys_get_abp_ns(mon_cb_param_t *param)
{
    int ret = 0;
    char value[32];

    log_dbg("start to get abp ns");

    ret = mon_util_redis_connect();
    if (ret != 0) {
        log_err("mon_util_redis_connect error");
        return -1;
    }

    memset(value, 0, sizeof(value));
    ret = mon_util_redis_get(abp_ns_limit_key, value, 32);
    if (strlen(value) > 0) {
        param->mon_sys.nodes_limit = atoi(value);
    } else {
        param->mon_sys.nodes_limit = 0;
    }

    memset(value, 0, sizeof(value));
    ret = mon_util_redis_get(abp_ns_stat_key, value, 32);
    if (strlen(value) > 0) {
        param->mon_sys.abp_ns_stat = 1;
    } else {
        param->mon_sys.abp_ns_stat = 0;
    }

    mon_util_redis_disconnect();

    return 0;
}
#endif

static int mon_sys_init(void)
{
    log_dbg("init start");
    mon_reg_cb(MON_SYS_FS, mon_sys_get_fs);
    mon_reg_cb(MON_SYS_CPU, mon_sys_get_cpu);
    mon_reg_cb(MON_SYS_MEM, mon_sys_get_memory);
    mon_reg_cb(MON_SYS_UPTIME, mon_sys_get_uptime);
#ifdef MONITOR_SYS_TEMP
    mon_reg_cb(MON_SYS_TEMP, mon_sys_get_temp);
#endif
#ifdef MONITOR_SYS_BAT
    mon_reg_cb(MON_SYS_BAT, mon_sys_get_bat);
#endif
#ifdef MONITOR_SYS_ABP_NS
    mon_reg_cb(MON_SYS_ABP_NS, mon_sys_get_abp_ns);
#endif
    return 0;
}

static int (*_mon_sys_init)(void) __init_call = mon_sys_init;
