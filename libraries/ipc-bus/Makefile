.PHONY: all

ENABLE_ALILOG_SUPPORT=true

ifeq ($(TOOLCHAIN_SYSROOT),)
CC = ${BUILDHOST}-gcc
else
CC = ${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}
endif

AR = ${BUILDHOST}-ar
CFLAGS  = -std=gnu99 -Wall -g -fPIC -I./include


NAME    := libipcbus
SNAME   := $(NAME).a
DNAME   := $(NAME).so

LDFLAGS +=  -L${BUILDROOT}/${BUILDOUTPUT}/lib/ -ldbus-1 -lexpat

CFLAGS += -I${BUILDROOT}/${BUILDOUTPUT}/include/
LDFLAGS += -lm -lrt 
ifeq ($(ENABLE_ALILOG_SUPPORT),true)
CFLAGS  += -DENABLE_REMOTE_LOG
LDFLAGS +=  -lalilog
endif

ifneq ($(dbus_address), )
CFLAGS  += -Dbus_address=\"$(dbus_address)\"
endif

all: ./src/loragw_interface_common.o $(SNAME) $(DNAME)

$(DNAME): ./src/loragw_interface_common.o
		$(CC) $(CFLAGS) -shared -fPIC -o $@ $^ $(LDFLAGS)

$(SNAME): ./src/loragw_interface_common.o
		$(AR) $(ARFLAGS) $@ $^ 

clean:
		rm -rf $(SNAME) $(DNAME)
		rm -rf ./src/*.o
