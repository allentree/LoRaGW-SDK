all: sshd_agent remote_debug
ENABLE_LOG_SUPPORT=true

SRCS += ./../connectivity/rd_net.c ./../connectivity/ws_nopoll.c ./sshd_agent.c
SRCS += ../utility/json/json_parser.c
SRCS += ../utility/ini/parser_ini.c
SRCS += ../utility/misc.c
SRCS += ../utility/sha256/hmac-sha256.c \
		../utility/sha256/sha256.c
CFLAGS = -fPIC -std=gnu99 -Wall -g
CFLAGS += -I./../connectivity -I${BUILDROOT}/${BUILDOUTPUT}/include -I${BUILDROOT}/${BUILDOUTPUT}/include/nopoll
CFLAGS += -I../utility/
CFLAGS += -I../utility/json/
CFLAGS += -I../utility/ini/
CFLAGS += -I../utility/sha256/
CFLAGS += -DPLATFORM_Lora
CFLAGS += -DNOPOLL_HAVE_TLSv11_ENABLED -DNOPOLL_HAVE_TLSv12_ENABLED -DNOPOLL_HAVE_TLSv10_ENABLED
LDFLAGS = -L${BUILDROOT}/${BUILDOUTPUT}/lib/

LIBS += -ldl -lssl -lcrypto -lpthread
ifeq ($(ENABLE_LOG_SUPPORT),true)
CFLAGS  += -DLOG_SUPPORT
LDFLAGS += -lalilog
endif

LDFLAGS += -lgwiotapi
#LDFLAGS += -L/chunk/wenhu.xwh/toolchain/LinkLoRa/arm-2011.03/arm-none-linux-gnueabi/libc/usr/lib
#RPATH = $(LDFLAGS)
sshd_agent: sshd_agent.c
	$(CC) -o sshd_agent $(SRCS) ${BUILDROOT}/${BUILDOUTPUT}/lib/libnopoll.a $(CFLAGS) $(LDFLAGS) $(LIBS)
	rm -f *.o
remote_debug:
	$(CC) -o remote_debug remote_debug.c

#all: sshd_agent remote_debug

clean:
	rm -rf *.o sshd_agent remote_debug
