#include <stdint.h>     /* C99 types */
#include <stdbool.h>    /* bool type */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

uint64_t pre_cpu_sum = 0;
uint64_t pre_cpu_idle = 0;

static int get_cpu_stat(struct cpu_stat_s* cpu_stat)
{
    FILE *fp;
    char buff[512];

    fp = fopen ("/proc/stat", "r");
    if (NULL == fp) {
        printf("fopen /proc/stat file error");
        return -1;
    }

    fgets (buff, sizeof(buff), fp);
    //printf("%s", buff);
    sscanf (buff, "%s %llu %llu %llu %llu %llu %llu %llu %llu ", cpu_stat->cpu_name, &cpu_stat->user, &cpu_stat->nice, &cpu_stat->system, 
                &cpu_stat->idle, &cpu_stat->iowait, &cpu_stat->irq, &cpu_stat->softirq, &cpu_stat->steal); 
    //printf("%s %llu %llu %llu %llu %llu %llu %llu %llu\n", cpu_stat->cpu_name, cpu_stat->user, cpu_stat->nice, cpu_stat->system,
    //            cpu_stat->idle, cpu_stat->iowait, cpu_stat->irq, cpu_stat->softirq, cpu_stat->steal);

    fclose(fp);

    return 0;
}

int get_cpu_ratio(float* cpu_ratio)
{
    struct cpu_stat_s cpu_stat;
    uint64_t cpu_sum = 0;
    uint64_t cpu_sum_diff = 0;
    uint64_t cpu_idle_diff = 0;
    int ret = 0;
    
    *cpu_ratio = 0.0;

    ret = get_cpu_stat(&cpu_stat);
    if (ret == 0) {
        cpu_sum = cpu_stat.user + cpu_stat.nice + cpu_stat.system + cpu_stat.idle 
                + cpu_stat.iowait + cpu_stat.irq + cpu_stat.softirq + cpu_stat.steal;
        //printf("idle: %llu\n", cpu_stat.idle);
        //printf("cpu_sum: %llu\n", cpu_sum);
        cpu_idle_diff = cpu_stat.idle - pre_cpu_idle;
        cpu_sum_diff = cpu_sum - pre_cpu_sum;
        //printf("idle_diff: %llu\n", cpu_idle_diff);
        //printf("sum_diff: %llu\n", cpu_sum_diff);
 
        if (cpu_sum_diff != 0) {
            *cpu_ratio = (float)(cpu_sum_diff - cpu_idle_diff) / (float)cpu_sum_diff;
        }

        pre_cpu_idle = cpu_stat.idle;
        pre_cpu_sum = cpu_sum;
    }

    printf("cpu_ratio: %.1f\n", (*cpu_ratio) * 100.0);

    return 0;
}

int get_mem_ratio(float* mem_ratio)
{
    FILE *fp = NULL;
    char buff[256] = {0};
    char mem_name[32] = {0};
    uint32_t mem_total = 0;
    uint32_t mem_free  = 0;
    uint32_t mem_used  = 0;
    uint32_t mem_cached = 0;
	uint32_t mem_buffers = 0;
	
	uint32_t mem_tmp = 0;
    uint8_t get_cached_mem = 0;
	uint8_t get_buffers_mem = 0;
	
    *mem_ratio = 0.0;

    fp = fopen ("/proc/meminfo", "r");
    if (NULL == fp) {
        printf("fopen /proc/meminfo file error");
        return -1;
    }

    fgets (buff, sizeof(buff), fp);
    sscanf (buff, "%s %u ", mem_name, &mem_total);
    //printf("%s", buff);

    fgets (buff, sizeof(buff), fp);
    //printf("%s", buff);
    sscanf (buff, "%s %u ", mem_name, &mem_free);
    while(fgets (buff, sizeof(buff), fp)){
        sscanf (buff, "%s %u ", mem_name, &mem_tmp);
        if(strncmp(mem_name , "Cached", strlen("Cached")) == 0){
            get_cached_mem = 1;
			mem_cached = mem_tmp ;
        }
		else if(strncmp(mem_name , "Buffers", strlen("Buffers")) == 0){
            get_buffers_mem = 1;
			mem_buffers = mem_tmp ;
        }
		if(get_cached_mem && get_buffers_mem)
			break;
    }
	
    mem_used = mem_total - mem_free;
    if(get_cached_mem) {
        mem_used -= mem_cached;
    }
	if(get_buffers_mem) {
		mem_used -= mem_buffers;
	}
    //printf("mem_used: %14u kB\n", mem_used);
    if (mem_total != 0) {
    	*mem_ratio = (float)mem_used / (float)mem_total;
    }

    printf("mem_ratio: %.1f\n", (*mem_ratio) * 100.0);

    fclose(fp);

    return 0;
}

