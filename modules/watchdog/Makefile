.PHONY: all


ENABLE_ALILOG_SUPPORT=true


ifeq ($(TOOLCHAIN_SYSROOT),)
CC = ${BUILDHOST}-gcc
else
CC = ${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}
endif

CFLAGS  = -std=gnu99 -O2 -Wall -Wextra 
LDFLAGS = -L${BUILDROOT}/${BUILDOUTPUT}/lib

ifeq ($(ENABLE_ALILOG_SUPPORT),true)
CFLAGS  += -DENABLE_REMOTE_LOG
LDFLAGS += -lalilog
endif

CFLAGS += -DDBUS_SUPPORT_SERVER_PID


ifneq ($(dbus_address), )
CFLAGS += -Dbus_address=\"$(dbus_address)\"
endif

LDFLAGS += -lcjson -ldbus-1 -lexpat


LDFLAGS += -lm -pthread -lrt

INCLUD_PATH += -I./src/
INCLUD_PATH += -I./src/api
INCLUD_PATH += -I${BUILDROOT}/${BUILDOUTPUT}/include/

BIN_SRC_FILE = $(wildcard src/*.c)
LIB_SRC_FILE += $(wildcard src/api/*.c)
TEST_SRC_FILE = $(wildcard unittest/lora_watchdog_test.c)

bin_TARGET = watchdog
lib_TARGET = libwatchdog.so
test_TARGET = lora_watchdog

all:
	$(CC) $(CFLAGS) $(INCLUD_PATH) -o $(bin_TARGET) $(BIN_SRC_FILE) $(LDFLAGS) 
	$(CC) $(CFLAGS) -shared -fPIC  -o $(lib_TARGET) $(INCLUD_PATH) $(LIB_SRC_FILE) $(LDFLAGS)
	$(CC) $(CFLAGS) $(INCLUD_PATH) -o $(test_TARGET) $(TEST_SRC_FILE) $(LDFLAGS) -L./ -lwatchdog
clean:
	rm -rf $(bin_TARGET) $(lib_TARGET) $(test_TARGET)
	rm -rf src/*.o
	rm -rf src/api/*.o
	rm -rf unittest/*.o
