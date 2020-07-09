.PHONY: all

#include ./../make.settings
ENABLE_WATCHDOG_SUPPORT=true
ENABLE_ALILOG_SUPPORT=true
ENABLE_MONITOR_SUPPORT=true

ENABLE_CUSTOM_OTA_PATH=false
#change the OTA path here
CUSTOM_OTA_PATH="/usr/tmp/lora_ota/"

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
LDFLAGS +=-lwatchdog
CFLAGS += -DENABLE_WATCHDOG
endif

ifeq ($(ENABLE_MONITOR_SUPPORT),true)
INCLUD_PATH += -I../monitor/include
CFLAGS += -DENABLE_MONITOR
endif

ifeq ($(ENABLE_CUSTOM_OTA_PATH),true)
CFLAGS += -DOTA_STORE_DIR=\"$(CUSTOM_OTA_PATH)\"
endif

LDFLAGS += -lm -pthread -lrt
LDFLAGS += -lgwiotapi
LDFLAGS += -ldbus-1  -lexpat  -lcjson
LDFLAGS += -ldl -lssl -lcrypto
INCLUD_PATH += -I${BUILDROOT}/${BUILDOUTPUT}/include/iotkit/
INCLUD_PATH += -I./include

INCLUD_PATH += -I${BUILDROOT}/${BUILDOUTPUT}/include/



SRC_FILE =  ./src/ecdsa_operation.c
SRC_FILE += ./src/ota_utils.c
SRC_FILE += ./src/sysconfig.c
SRC_FILE += ./src/update_ipc_local.c
SRC_FILE += ./src/main.c

TARGET = update-deamon


all:
	$(CC) $(CFLAGS) $(INCLUD_PATH) -o $(TARGET) $(SRC_FILE) $(BUILDROOT)/$(BUILDOUTPUT)/lib/libipcbus.a $(LDFLAGS) 
	$(CC) $(CFLAGS) $(INCLUD_PATH) -o lora_sign ./src/ecdsa_operation.c ./src/lora_sign_test.c -L${BUILDROOT}/${BUILDOUTPUT}/lib -ldl -lssl -lcrypto
	#gcc $(CFLAGS) $(INCLUD_PATH) -o lora_sign ./src/ecdsa_operation.c ./src/lora_sign_test.c -ldl -L$(BUILDROOT)/$(BUILDOUTPUT)/lib/ -lssl -lcrypto
clean:
	 rm -rf $(TARGET) lora_sign
