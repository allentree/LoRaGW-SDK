NO_RSVD_PART_SUPPORT := Y
ENABLE_ALILOG_SUPPORT=$(ENABLE_ALILOG)
ENABLE_WATCHDOG_SUPPORT=$(ENABLE_WATCHDOG)

ifeq ($(NO_RSVD_PART_SUPPORT), Y)
SRV_CFLAGS += -DNO_RSVD_PART_SUPPORT=1
endif

SRCS += keychain.c main.c kcManage.c ../utils/file_operation.c
SDK_OBJS += keychain.o
SDK += libkeychain.a
SRV_OBJS += main.o kcManage.o ../utils/file_operation.o
SRV += keychain_service

ifneq ($(dbus_address), )
ACFLAGS  += -Dbus_address=\"$(dbus_address)\"
endif

ACFLAGS += -I${BUILDROOT}/${BUILDOUTPUT}/include/ \
		  -I../utils \
		  -I../../include

SRV_CFLAGS += -I../../include \

SRV_LDFLAGS += -L${BUILDROOT}/${BUILDOUTPUT}/lib/ -lirot

SRV_LDFLAGS += ../sst/src/libsst.a \
			   -L../../lib/$(board_arch)/ -lalicrypto \
			   -lmbedcrypto

ifeq ($(ENABLE_ALILOG_SUPPORT),true)
CFLAGS  += -DENABLE_REMOTE_LOG
SRV_LDFLAGS += -L${BUILDROOT}/${BUILDOUTPUT}/lib -lalilog
endif

ifeq ($(ENABLE_WATCHDOG_SUPPORT),true)
SRV_LDFLAGS += -L${BUILDROOT}/${BUILDOUTPUT}/lib -lwatchdog -lcjson
CFLAGS += -DENABLE_WATCHDOG
endif

all: $(SDK) $(SRV)

$(SDK_OBJS): %.o:%.c
	$(CC) -c $(CFLAGS) $(ACFLAGS) $(SDK_CFLAGS) $< -o $@  -fPIC
$(SRV_OBJS): %.o:%.c
	$(CC) -c $(CFLAGS) $(ACFLAGS) $(SRV_CFLAGS) $< -o $@  -fPIC
$(SDK): $(SDK_OBJS)
	$(AR) rc $(SDK) $(SDK_OBJS)
$(SRV): $(SRV_OBJS)
	$(CC) -o $(SRV) $(SRV_OBJS) $(LDFLAGS) $(SRV_LDFLAGS) -L${BUILDROOT}/${BUILDOUTPUT}/lib/  -ldbus-1
install :
	install -m 755 keychain_service ${BUILDROOT}/${BUILDOUTPUT}/bin
	cp libkeychain.a ${BUILDROOT}/${BUILDOUTPUT}/lib
clean:
	rm -rf $(SDK_OBJS) $(SRV_OBJS) $(SDK) $(SRV)

