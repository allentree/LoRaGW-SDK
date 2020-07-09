#ifndef _MONITOR_INTERFACE_EXPORT_H_
#define _MONITOR_INTERFACE_EXPORT_H_

#define MONITOR_WELL_KNOWN_NAME "iot.gateway.monitor"
#define MONITOR_INTERFACE_NAME "iot.gateway.monitor"
#define MONITOR_OBJECT_NAME "/iot/gateway/monitor"

//TODO : 是否修改为method调用
#define MON_GWMP_DLINK_SIGNAL "monitor_gwmp_dlink"
#define MON_ALARM_SIGNAL "monitor_alarm_assert"

#define MAX_ALARM_PAYLOAD_LEN (256)

typedef enum {
    MON_ALARM_SX1301 = 0,
    MON_ALARM_DMESG,
    MON_ALARM_REBOOT
} mon_alarm_type_t;


#endif
