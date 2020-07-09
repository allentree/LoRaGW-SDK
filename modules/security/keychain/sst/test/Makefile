DATA_MIGRATION := Y
SST_MIGRATION := N
ID2_SUPPORT := N
LINUX_TEST_BIN := Y
ENABLE_ALILOG_SUPPORT=$(ENABLE_ALILOG)

TEST_LIBS := libsst_test.a
TEST_BINS := sst_test

ifeq ($(SST_MIGRATION), Y)
ACFLAGS += -DCONFIG_SST_MIGRATION=1
SRCS += sst_test_migfile.c
endif

ifeq ($(DATA_MIGRATION), Y)
ACFLAGS += -DCONFIG_DATA_MIGRATION=1
SRCS +=	sst_test_migration.c
endif

SRCS += sst_test_basic.c \
		sst_test_performance.c

ifeq ($(LINUX_TEST_BIN), Y)
SRCS += sst_test_main.c
ALDFLAGS += ../src/libsst.a \
		   -L${BUILDROOT}/${BUILDOUTPUT}/lib/ -lirot \
		   -L../../../lib/$(board_arch)/ -lalicrypto \
		   -L../../../lib/$(board_arch)/ -lmbedcrypto \
		   -L${BUILDROOT}/${BUILDOUTPUT}/lib/ -ldbus-1

ifeq ($(ENABLE_ALILOG_SUPPORT),true)
CFLAGS  += -DENABLE_REMOTE_LOG
ALDFLAGS += -L${BUILDROOT}/${BUILDOUTPUT}/lib -lalilog
endif

all: $(TEST_BINS)
else
all: $(TEST_LIBS)
endif
TEST_OBJS := $(patsubst %.c, %.o, $(SRCS))

ACFLAGS += -I../../../include
ACFLAGS += -DIROT_SUPPORT=1

%.o: %.c
	$(CC) -std=c99 $(CFLAGS) $(ACFLAGS) -c $^ -o $@

$(TEST_LIBS): $(TEST_OBJS)
	$(AR) rc $(TEST_LIBS) $(TEST_OBJS)

$(TEST_BINS): $(TEST_OBJS)
	$(CC) -std=c99 -o $(TEST_BINS) $(TEST_OBJS) $(ALDFLAGS) $(LDFLAGS)

install :
	install -m 755 sst_test ${BUILDROOT}/${BUILDOUTPUT}/bin

.PHONY: clean
clean:
	$(RM) $(TEST_OBJS) $(TEST_BINS) $(TEST_LIBS)

