NO_RSVD_PART_SUPPORT := Y

ifeq ($(NO_RSVD_PART_SUPPORT), Y)
ACFLAGS += -DNO_RSVD_PART_SUPPORT=1
endif

SRCS += deploy_sst.c ../utils/file_operation.c
OBJS := $(patsubst %.c, %.o, $(SRCS))
BINS := deploy_sst

ACFLAGS += -I../../include \
		   -I../utils

ALDFLAGS += ../sst/src/libsst.a \
		   ../../lib/$(board_arch)/libkm.a \
		   ../../lib/$(board_arch)/libplat_gen.a \
		   -L../../lib/$(board_arch)/ -lalicrypto \
		   -lmbedcrypto

all:$(BINS)

$(OBJS): %.o:%.c
	$(CC) -c $(CFLAGS) $(ACFLAGS) $(SDK_CFLAGS) $< -o $@  -fPIC
$(BINS): $(OBJS)
	$(CC) -o $(BINS) $(OBJS) $(LDFLAGS) $(ALDFLAGS)
install :
	install -m 755 $(BINS) ${BUILDROOT}/${BUILDOUTPUT}/bin
clean:
	rm -rf $(BINS) $(OBJS)

