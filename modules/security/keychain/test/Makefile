ENABLE_ALILOG_SUPPORT=$(ENABLE_ALILOG)

OBJS := $(patsubst %.c, %.o, $(SRCS))
BINS += sec_sst_test_basic \
		sec_sst_test_store \
		sec_sst_test_get \
		sec_sst_test_exp \
		sec_sst_test_func \
		sec_sst_test_performance \
		sec_sst_test_same_uid \
		sec_sst_test_migration \
		sec_sst_test_domain \
		sec_sst_test_delete

ifneq ($(dbus_address), )
ACFLAGS  += -Dbus_address=\"$(dbus_address)\"
endif

ACFLAGS += -I../../include/
ACFLAGS += -I${BUILDROOT}/${BUILDOUTPUT}/include/
ALDFLAGS += -L${BUILDROOT}/${BUILDOUTPUT}/lib/  -lkeychain \
		  -L${BUILDROOT}/${BUILDOUTPUT}/lib/  -ldbus-1

ifeq ($(ENABLE_ALILOG_SUPPORT),true)
CFLAGS  += -DENABLE_REMOTE_LOG
ALDFLAGS += -L${BUILDROOT}/${BUILDOUTPUT}/lib -lalilog
endif

all:
	$(CC) -std=c99 -o sec_sst_test_basic $(CFLAGS) $(ACFLAGS) sec_sst_test_basic.c $(ALDFLAGS) $(LDFLAGS)
	$(CC) -std=c99 -o sec_sst_test_store $(CFLAGS) $(ACFLAGS) sec_sst_test_store.c $(ALDFLAGS) $(LDFLAGS)
	$(CC) -std=c99 -o sec_sst_test_get $(CFLAGS) $(ACFLAGS) sec_sst_test_get.c $(ALDFLAGS) $(LDFLAGS)
	$(CC) -std=c99 -o sec_sst_test_exp $(CFLAGS) $(ACFLAGS) sec_sst_test_exp.c $(ALDFLAGS) $(LDFLAGS)
	$(CC) -std=c99 -o sec_sst_test_func $(CFLAGS) $(ACFLAGS) sec_sst_test_func.c $(ALDFLAGS) $(LDFLAGS)
	$(CC) -std=c99 -o0 -g -o sec_sst_test_performance $(CFLAGS) $(ACFLAGS) sec_sst_test_performance.c $(ALDFLAGS) $(LDFLAGS) -lpthread
	$(CC) -std=c99 -o sec_sst_test_same_uid $(CFLAGS) $(ACFLAGS) sec_sst_test_same_uid.c $(ALDFLAGS) $(LDFLAGS) -lpthread
	$(CC) -std=c99 -o sec_sst_test_migration $(CFLAGS) $(ACFLAGS) sec_sst_test_migration.c $(ALDFLAGS) $(LDFLAGS)
	$(CC) -std=c99 -o sec_sst_test_domain $(CFLAGS) $(ACFLAGS) sec_sst_test_domain.c $(ALDFLAGS) $(LDFLAGS)
	$(CC) -std=c99 -o sec_sst_test_delete $(CFLAGS) $(ACFLAGS) sec_sst_test_delete.c $(ALDFLAGS) $(LDFLAGS)

clean:
	rm -rf $(BINS) $(OBJS) $(LIBS)

install :
	install -m 755 $(BINS) ${BUILDROOT}/${BUILDOUTPUT}/bin

.PHONY: clean

