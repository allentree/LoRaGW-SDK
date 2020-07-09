### Application-specific constants

APP_NAME := lora_pkt_fwd
ENABLE_WATCHDOG_SUPPORT=true
ENABLE_ALILOG_SUPPORT=true
ENABLE_MONITOR_SUPPORT=true
ENABLE_ADVANCED_OTA_SUPPORT=true
### Environment constants 

LGW_PATH ?= ../../lora_gateway/libloragw
ARCH ?=
CROSS_COMPILE ?=

ENABLE_IPC1=
ENABLE_IPC2=
DBUS_IPC_LIBS=

OBJDIR = obj
INCLUDES = $(wildcard inc/*.h)

### External constant definitions
# must get library build option to know if mpsse must be linked or not

include $(LGW_PATH)/library.cfg
RELEASE_VERSION := `cat ../VERSION`

### Constant symbols

ifeq ($(TOOLCHAIN_SYSROOT),)
CC := $(CROSS_COMPILE)gcc
else
CC := $(CROSS_COMPILE)gcc --sysroot=${TOOLCHAIN_SYSROOT}
endif
AR := $(CROSS_COMPILE)ar

CFLAGS := -O2 -Wall -Wextra -std=c99 -Iinc -I.
VFLAG := -D VERSION_STRING="\"$(RELEASE_VERSION)\""

### Constants for Lora concentrator HAL library
# List the library sub-modules that are used by the application

LGW_INC =
ifneq ($(wildcard $(LGW_PATH)/inc/config.h),)
  # only for HAL version 1.3 and beyond
  LGW_INC += $(LGW_PATH)/inc/config.h
endif
LGW_INC += $(LGW_PATH)/inc/loragw_hal.h
LGW_INC += $(LGW_PATH)/inc/loragw_gps.h

### Linking options

LIBS = -L$(LGW_PATH) -lloragw -lrt -lpthread -lm 

ifeq ($(BUILD_PKTFWD_BIN),true)
SDK_LIB_PATH = ${BUILDROOT}/${BUILDOUTPUT}/lib/
CFLAGS += -I${BUILDROOT}/${BUILDOUTPUT}/include/
endif

ifeq ($(ENABLE_WATCHDOG_SUPPORT),true)
LIBS += -L$(SDK_LIB_PATH) -lwatchdog -L$(SDK_LIB_PATH) -lcjson -L$(SDK_LIB_PATH) -ldbus-1
CFLAGS += -DENABLE_WATCHDOG
endif

ifeq ($(ENABLE_ALILOG_SUPPORT),true)
LIBS += -L$(SDK_LIB_PATH) -lalilog 
CFLAGS += -DENABLE_REMOTE_LOG
endif

ifeq ($(ENABLE_ADVANCED_OTA_SUPPORT),true)
CFLAGS += -DENABLE_ADVANCED_OTA
ENABLE_IPC2 = true
endif

ifeq ($(ENABLE_MONITOR_SUPPORT),true)
CFLAGS += -DENABLE_MONITOR
ENABLE_IPC2 = true
endif

ifneq ($(ENABLE_IPC1)$(ENABLE_IPC2),$(ENABLE_IPC_NULL))
LIBS += $(BUILDROOT)/$(BUILDOUTPUT)/lib/libipcbus.a
LIBS += -L$(SDK_LIB_PATH) -ldbus-1 -lexpat
CFLAGS += -DENABLE_DBUS_IPC
endif


### General build targets

all: $(APP_NAME)

clean:
	rm -f $(OBJDIR)/*.o
	rm -f $(APP_NAME)

### Sub-modules compilation

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c $(INCLUDES) | $(OBJDIR)
	$(CC) -c $(CFLAGS) -I$(LGW_PATH)/inc $< -o $@

### Main program compilation and assembly

$(OBJDIR)/$(APP_NAME).o: src/$(APP_NAME).c $(LGW_INC) $(INCLUDES) | $(OBJDIR)
	$(CC) -c $(CFLAGS) $(VFLAG) -I$(LGW_PATH)/inc $< -o $@

$(APP_NAME): $(OBJDIR)/$(APP_NAME).o $(LGW_PATH)/libloragw.a $(OBJDIR)/parson.o $(OBJDIR)/base64.o $(OBJDIR)/jitqueue.o $(OBJDIR)/timersync.o $(OBJDIR)/aes.o $(OBJDIR)/cmac.o $(OBJDIR)/lora_timesync.o $(OBJDIR)/ntp_time.o $(OBJDIR)/sys_stat.o $(OBJDIR)/filter_node.o $(OBJDIR)/pktfwd_ipc_local.o
	$(CC) $< $(OBJDIR)/parson.o $(OBJDIR)/base64.o $(OBJDIR)/jitqueue.o $(OBJDIR)/timersync.o $(OBJDIR)/aes.o $(OBJDIR)/cmac.o $(OBJDIR)/lora_timesync.o $(OBJDIR)/ntp_time.o $(OBJDIR)/sys_stat.o $(OBJDIR)/filter_node.o $(OBJDIR)/pktfwd_ipc_local.o $(LIBS) -o $@

### EOF
