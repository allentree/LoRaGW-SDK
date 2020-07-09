.PHONY: all

#include ./../../make.settings

ifeq ($(TOOLCHAIN_SYSROOT),)
CC = ${BUILDHOST}-gcc
else
CC = ${BUILDHOST}-gcc --sysroot=${TOOLCHAIN_SYSROOT}
endif
AR = ${BUILDHOST}-ar

CFLAGS  = -std=gnu99 -Wall -g -fPIC -I../include -I../src/utils
LDFLAGS = -lm -lrt -L./ -lgwiotapi

NAME	:= libgwiotapi
SNAME	:= $(NAME).a
DNAME	:= $(NAME).so

all: $(SNAME) $(DNAME) gwiotapi_test

$(DNAME): gwiotapi.o ../src/utils/aes.o ../src/utils/parson.o
	$(CC) -shared -fPIC -o $@ $^
	
$(SNAME): gwiotapi.o ../src/utils/aes.o ../src/utils/parson.o
	$(AR) $(ARFLAGS) $@ $^

gwiotapi_test: gwiotapi_test.o
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)
	
clean:
	rm -rf $(SNAME) $(DNAME)
	rm -rf *.o
	rm -rf ../src/*.o
	rm -rf ../src/utils/*.o
