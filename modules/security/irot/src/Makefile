ENABLE_ALILOG_SUPPORT=$(ENABLE_ALILOG)
ENABLE_WATCHDOG_SUPPORT=$(ENABLE_WATCHDOG)


SRCS += irot_km.c IRotService.c IRotKm.c
SDK_OBJS += irot_km.o
SDK += libirot.a
SRV_OBJS += IRotService.o IRotKm.o
SRV += irot_service

ifneq ($(dbus_address), )
ACFLAGS  += -Dbus_address=\"$(dbus_address)\"
endif

ACFLAGS += -I${BUILDROOT}/${BUILDOUTPUT}/include

SDK_CFLAGS += -I../../include

SRV_CFLAGS += -I../../include

SRV_LDFLAGS += ../../lib/$(board_arch)/libkm.a \
			   ../../lib/$(board_arch)/libplat_gen.a \
			   ../../lib/$(board_arch)/libalicrypto.a \
			   ../../lib/$(board_arch)/libmbedcrypto.a

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
	$(CC) -o $(SRV) $(SRV_OBJS) $(SRV_LDFLAGS) -L${BUILDROOT}/${BUILDOUTPUT}/lib -ldbus-1

install :
		install -m 755 irot_service ${BUILDROOT}/${BUILDOUTPUT}/bin
		cp libirot.a ${BUILDROOT}/${BUILDOUTPUT}/lib
clean:
	rm -rf $(SDK_OBJS) $(SRV_OBJS) $(SDK) $(SRV)
