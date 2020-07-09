AES_SUPPORT := Y
HMAC_SUPPORT := Y
RSA_SUPPORT := Y
ID2_SUPPORT := Y
ENVELOPE_SUPPORT := Y
LINUX_TEST_BIN := Y
ENABLE_ALILOG_SUPPORT=$(ENABLE_ALILOG)

BINS := km_test
LIBS := libkm_test.a

SRCS += km_test.c \
		km_test_comm.c

ACFLAGS += -I./inc
ACFLAGS += -I../../include/

ifeq ($(TEST_DEBUG), Y)
ACFLAGS += -DKM_TEST_DEBUG=1
endif

ifeq ($(AES_SUPPORT), Y)
ACFLAGS += -DCONFIG_AES_SUPPORT=1
SRCS += km_test_aes.c
endif

ifeq ($(HMAC_SUPPORT), Y)
ACFLAGS += -DCONFIG_HMAC_SUPPORT=1
SRCS += km_test_mac.c
endif

ifeq ($(RSA_SUPPORT), Y)
ACFLAGS += -DCONFIG_RSA_SUPPORT=1
SRCS += km_test_rsa.c
endif

ifeq ($(ID2_SUPPORT), Y)
ACFLAGS += -DCONFIG_ID2_SUPPORT=1
SRCS += km_test_id.c
endif

ifeq ($(ENVELOPE_SUPPORT), Y)
ACFLAGS += -DCONFIG_ENVELOPE_SUPPORT=1
SRCS += km_test_envelope.c
endif

ifeq ($(LINUX_TEST_BIN), Y)
ACFLAGS += -DLINUX_TEST_BIN
all:$(BINS)
else
all:$(LIBS)
endif


ALDFLAGS += -lpthread \
            -L${BUILDROOT}/${BUILDOUTPUT}/lib/ -lirot \
	    -ldbus-1

ifeq ($(ENABLE_ALILOG_SUPPORT),true)
CFLAGS  += -DENABLE_REMOTE_LOG
ALDFLAGS += -L${BUILDROOT}/${BUILDOUTPUT}/lib -lalilog
endif

OBJS := $(patsubst %.c, %.o, $(SRCS))
%.o:%.c
	$(CC) -c $(CFLAGS) $(ACFLAGS) $^ -o $@

$(BINS): $(OBJS)
	$(CC) -o $(BINS) $(OBJS) $(LDFLAGS) $(ALDFLAGS)

$(LIBS): $(OBJS)
	$(AR) rc $(LIBS) $(OBJS)

clean:
	rm -rf $(BINS) $(OBJS) $(LIBS)
install :
	install -m 755 km_test ${BUILDROOT}/${BUILDOUTPUT}/bin
.PHONY: clean

