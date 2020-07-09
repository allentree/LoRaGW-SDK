#include "_watchdog_includes.h"
#include "_watchdog_system_feed.h"
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/watchdog.h>


int sys_wdg_fd = -1;
int sys_wdg_inited = 0;
int _watchdog_system_feeddog_setup(const char * dev_name, int interval)
{
	int ret;
	int data ;
	if(sys_wdg_inited)
	{
		return WATCHDOG_ERROR_SUCEESS;
	}
	if(!dev_name || strlen(dev_name) == 0)
	{
		return WATCHDOG_ERROR_INVALID_PARAM;
	}
	if(interval <= 0 || interval > 60)
	{
		log_info( "system watchdog feed time should be 1-60 S!\n ");
		return WATCHDOG_ERROR_INVALID_PARAM;
	}
	sys_wdg_fd = open(dev_name, O_WRONLY);
	if(sys_wdg_fd < 0)
	{
		log_err("open system watchdog error! errno : %d !\n", dev_name, errno);
		return WATCHDOG_ERROR_IO;
	}
	
	ioctl (sys_wdg_fd, WDIOC_GETTIMEOUT, &data);
	
	data = interval;
	ioctl (sys_wdg_fd, WDIOC_SETTIMEOUT, &data);

	//todo : set nowayout enabled
	
	sys_wdg_inited = 1;
	return WATCHDOG_ERROR_SUCEESS;
}

int _watchdog_system_feeddog()
{
	if(!sys_wdg_inited)
	{
		return WATCHDOG_ERROR_IO;
	}
	
	if (sys_wdg_fd > 0)
		write(sys_wdg_fd, "a", 1);
	return WATCHDOG_ERROR_SUCEESS;
}

int _watchdog_system_feeddog_exit()
{
	if(!sys_wdg_inited)
	{
		return WATCHDOG_ERROR_IO;
	}
	
	write(sys_wdg_fd, "V", 1);
	close(sys_wdg_fd);
	sys_wdg_fd = -1;
	sys_wdg_inited = 0;
	return WATCHDOG_ERROR_SUCEESS;
}
/*
定时让cron去执行cron_watchdog.sh脚本，这个脚本里去检查watchdog是否正在运行，如果不在运行则reboot
cron_watchdog.sh 存放在和watchdog相同的目录。
cron_watchdog.sh 内容如下：
#!/bin/bash
pgrep watch_dog;
if [[ $? -ne 0 ]];
then
/sbin/reboot;
fi

*/
static int create_crontab()
{
    char str_exe[FILENAME_MAX + 1];
    int fn_str_len = readlink("/proc/self/exe", str_exe, FILENAME_MAX);
    if (fn_str_len < 0) {
        return -1;
    }
	if(fn_str_len == FILENAME_MAX) {
		return -1;
	}
    str_exe[fn_str_len] = '\0';
	char *exe_start = strrchr(str_exe, '/');
	if(exe_start == NULL)
		return -1;
	exe_start ++;
	*exe_start = '\0';
	
	strcat(str_exe, CRON_WATCH_SHELL);
	
    char str_crontab[FILENAME_MAX];
    snprintf(str_crontab, FILENAME_MAX, "*/1 *     * * *     root [ -x %s ] && %s", str_exe, str_exe);
    FILE *fh_crontab = fopen("/etc/cron.d/gateway_watchdog", "w");
    if (fh_crontab) {
        fputs(str_crontab, fh_crontab);
        fclose(fh_crontab);
        log_info( "crontab created at /etc/cron.d/gateway_watchdog, \r\n"
              "  crontab content: %s",
              str_crontab);
		return WATCHDOG_ERROR_SUCEESS;
    } else {
        log_err( "unable to create /etc/cron.d/gateway_watchdog, \r\n"
              "  crontab content: %s",
              str_crontab);
		return WATCHDOG_ERROR_IO;
    }
	return WATCHDOG_ERROR_SUCEESS;
}

int _watchdog_system_crond_setup()
{
	//判断 /etc/cron.d文件是否存在？
	if(access("/etc/cron.d", F_OK) < 0)
	{
		log_err( "there is no crond on target barod!!\n\r");
		return WATCHDOG_ERROR_IO;
	}
	//添加crontab，每分钟检测watchdog进程，如果watchdog没有在运行，重启lora网关
	
	if(create_crontab() != WATCHDOG_ERROR_SUCEESS)
	{
		return WATCHDOG_ERROR_IO;
	}

	//判断crond是否运行，没有运行怎启动crond
	//system("service corn restart");
	return WATCHDOG_ERROR_SUCEESS;
}

