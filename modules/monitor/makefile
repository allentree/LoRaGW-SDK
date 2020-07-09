.PHONY: all

include make.settings
include ./../../libraries/iotkit-embedded/make.settings

ifeq ($(TOOLCHAIN_SYSROOT),)
CC = ${BUILDHOST}-gcc
else
CC = ${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}
endif
CFLAGS  = -std=gnu99 -Wall -g -I../mqtt/include
LDFLAGS = 
LDEXTFLAGS =
DBUS_PATH = $(BUILDROOT)/$(BUILDOUTPUT)
HIREDIS_LIBS =

ifeq ($(ENABLE_ALILOG_SUPPORT),true)
    CFLAGS  += -DENABLE_REMOTE_LOG
    LDFLAGS += -lalilog
endif

ifeq ($(MONITOR_INTERVAL_ENABLED),y)
    CFLAGS  += -DMON_INTERVAL="$(MONITOR_INTERVAL)"
else
    CFLAGS  += -DMON_INTERVAL=60
endif

ifeq ($(CC), $(filter $(CC), cc gcc))
    DBUS_CFLAGS := -I /usr/lib/x86_64-linux-gnu/dbus-1.0/include -I /usr/include/dbus-1.0
    DBUS_LIBS := -ldbus-1
else

    DBUS_CFLAGS := -I$(DBUS_PATH)/include -I$(DBUS_PATH)/include/dbus-1.0 -I$(DBUS_PATH)/lib/dbus-1.0/include/
    DBUS_LIBS := -L$(DBUS_PATH)/lib -ldbus-1  -Wl,--rpath-link $(DBUS_PATH)/lib
ifeq ($(ENABLE_WATCHDOG_SUPPORT),true)   
    DBUS_LIBS += -lwatchdog
    CFLAGS += -DLORAGW_WATCHDOG_ENABLED
endif
endif

LDFLAGS += -lm -pthread -lrt $(DBUS_LIBS)

INCLUDE_PATH = -I./include -I../include 
INCLUDE_PATH +=  $(DBUS_CFLAGS)

SRC_FILE =  ./src/mon_main.c
SRC_FILE += ./src/mon_util.c
SRC_FILE += ./src/monitor_ipc_local.c

ifeq ($(MONITOR_SYS_ENABLED),y)
    SRC_FILE += ./src/mon_system.c

    ifeq ($(MONITOR_SYS_BAT_ENABLED),y)
        CFLAGS  += -DMONITOR_SYS_BAT

        ifeq ($(MONITOR_SYS_BAT_EXT_ENABLED),y)
            CFLAGS  += -DMONITOR_SYS_BAT_EXT
            LDEXTFLAGS = -L. -lmon_ext_api
        endif
    endif

    ifeq ($(MONITOR_SYS_TEMP_ENABLED),y)
        CFLAGS  += -DMONITOR_SYS_TEMP

        ifeq ($(MONITOR_SYS_TEMP_EXT_ENABLED),y)
            CFLAGS  += -DMONITOR_SYS_TEMP_EXT
            LDEXTFLAGS = -L. -lmon_ext_api
        endif
    endif

    ifeq ($(MONITOR_SYS_FS_EXT_ENABLED),y)
        CFLAGS  += -DMONITOR_SYS_FS_EXT
        LDEXTFLAGS = -L. -lmon_ext_api
    endif

    ifeq ($(MONITOR_SYS_ABP_NS_ENABLED),y)
        CFLAGS  += -DMONITOR_SYS_ABP_NS
        HIREDIS_LIBS = ${BUILDROOT}/${BUILDOUTPUT}/lib/libhiredis.a
    endif

endif

ifeq ($(MONITOR_BACKHAUL_ENABLED),y)
    SRC_FILE += ./src/mon_backhaul.c
endif

ifeq ($(MONITOR_BACKHAUL_PING_ENABLED),y)

    SRC_FILE += ./src/mon_backhaul_ping.c

    ifeq ($(MONITOR_EXT_PING_ENABLED), y)
        CFLAGS  += -DMON_EXT_PING
    endif

endif

ifeq ($(MONITOR_DMESG_ENABLED),y)
    SRC_FILE += ./src/mon_dmesg.c
endif

ifeq ($(ENABLE_ADVANCED_OTA_SUPPORT),true)
    CFLAGS  += -DENABLE_ADVANCED_OTA
endif

TARGET = monitor

all:
	$(CC) $(CFLAGS) $(INCLUDE_PATH) -o $(TARGET) $(SRC_FILE) $(BUILDROOT)/$(BUILDOUTPUT)/lib/libipcbus.a ${HIREDIS_LIBS} $(LDFLAGS) $(LDEXTFLAGS)

clean:
	rm -rf $(TARGET)
