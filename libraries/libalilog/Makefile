all: libalilog.so log_test

ENABLE_OSS_UPLOAD=false
OSSLIBS=

ifeq ($(ENABLE_OSS_UPLOAD),true)
CFLAGS += -DENABLE_OSS_UPLOAD
OSSLIBS += $(ALILOG_LIB_PATH)/libcurl.a $(ALILOG_LIB_PATH)/libwolfssl.a
endif

ifeq ($(TOOLCHAIN_SYSROOT),)
CC = ${BUILDHOST}-gcc
LDFLAGS := -L$(ALILOG_LIB_PATH) -lpthread -lm -lrt
else
CC = ${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}
LDFLAGS := -L$(ALILOG_LIB_PATH) -lpthread -lm -lrt -lz
endif

CFLAGS += -Wall -Werror -fPIC
CFLAGS += $(ALILOG_CFLAGS)

libalilog.so: log.o log_file.o log_file_storage.o log_oss.o md5.o
	$(CC) -shared -fPIC -o libalilog.so $^ $(OSSLIBS) $(LDFLAGS) $(CFLAGS)

log_test: log.o log_file.o log_file_storage.o log_oss.o log_test.o md5.o
	$(CC) -o log_test $^ $(OSSLIBS) $(LDFLAGS) $(CFLAGS)

clean:
	rm -rf *.o libalilog.so log_test
install_inc:
	cp -a *.h $(PREFIX)/include/
install_lib:
	cp -a *.so $(PREFIX)/lib/

install: install_inc install_lib

