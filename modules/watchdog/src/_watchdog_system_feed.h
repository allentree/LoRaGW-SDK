#ifndef __WATCHDOG_SYSTEM_FEED_H_
#define __WATCHDOG_SYSTEM_FEED_H_


int _watchdog_system_feeddog_setup(const char * dev_name, int interval);
int _watchdog_system_feeddog();
int _watchdog_system_feeddog_exit();

#define CRON_WATCH_SHELL "cron_watchdog.sh"
int _watchdog_system_crond_setup();	
#endif