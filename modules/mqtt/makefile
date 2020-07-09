.PHONY: all

#include ./../make.settings
ENABLE_WATCHDOG_SUPPORT=true
ENABLE_ALILOG_SUPPORT=true
ENABLE_MONITOR_SUPPORT=true
ENABLE_ADVANCED_OTA_SUPPORT=true
ENABLE_ADVANCED_SECURITY_SUPPORT=true

ENABLE_IPC1=
ENABLE_IPC2=
DBUS_IPC_LIBS=
SECURITY_LIBS=

ifeq ($(TOOLCHAIN_SYSROOT),)
CC = ${BUILDHOST}-gcc
else
CC = ${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}
endif

CFLAGS  = -std=gnu99 -Wall -g
LDFLAGS = -L${BUILDROOT}/${BUILDOUTPUT}/lib

ifeq ($(ENABLE_ALILOG_SUPPORT),true)
CFLAGS  += -DENABLE_REMOTE_LOG
LDFLAGS += -lalilog
endif
ifeq ($(ENABLE_WATCHDOG_SUPPORT),true)
LDFLAGS += -lwatchdog -lcjson
CFLAGS += -DENABLE_WATCHDOG
LDFLAGS += -ldbus-1 -lexpat
endif

ifeq ($(ENABLE_MONITOR_SUPPORT),true)
INCLUD_PATH += -I../monitor/include
CFLAGS += -DENABLE_MONITOR
ENABLE_IPC1 = true
endif

ifeq ($(ENABLE_ADVANCED_OTA_SUPPORT),true)
CFLAGS += -DENABLE_ADVANCED_OTA
ENABLE_IPC2 = true
endif

ifneq ($(ENABLE_IPC1)$(ENABLE_IPC2),$(ENABLE_IPC_NULL))
DBUS_IPC_LIBS=$(BUILDROOT)/$(BUILDOUTPUT)/lib/libipcbus.a
LDFLAGS += -ldbus-1 -lexpat
CFLAGS += -DENABLE_DBUS_IPC
endif


ifeq ($(ENABLE_ADVANCED_SECURITY_SUPPORT),true)
CFLAGS += -DENABLE_ADVANCED_SECURITY
SECURITY_LIBS=$(BUILDROOT)/$(BUILDOUTPUT)/lib/libkeychain.a
LDFLAGS += -ldbus-1 -lexpat
endif

LDFLAGS += -lm -pthread -lrt
LDFLAGS += -liot_sdk -liot_hal
LDFLAGS += -liot_tls
LDFLAGS += -lgwiotapi
LDFLAGS += -ldl


INCLUD_PATH += -I${BUILDROOT}/${BUILDOUTPUT}/include/iotkit/
INCLUD_PATH += -I./include
INCLUD_PATH += -I./src/utils
INCLUD_PATH += -I${BUILDROOT}/${BUILDOUTPUT}/include/
INCLUD_PATH += -I${BUILDROOT}/libraries/iotkit-embedded/src/infra/utils
SRC_FILE = $(wildcard src/*.c)
SRC_FILE += $(wildcard src/utils/*.c)

TARGET = mqtt

all:
	$(CC) $(CFLAGS) $(INCLUD_PATH) -o $(TARGET) $(SRC_FILE) ${BUILDROOT}/${BUILDOUTPUT}/lib/libhiredis.a ${DBUS_IPC_LIBS} ${SECURITY_LIBS} $(LDFLAGS) 
	
clean:
	rm -rf $(TARGET)
	rm -rf src/*.o
	rm -rf src/utils/*.o
