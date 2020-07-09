SST_DBG := N
DATA_MIGRATION := Y
SST_MIGRATION := Y
ID2_SUPPORT := N

LIBS := libsst.a

LOCAL_DIR := .

ACFLAGS += -I../../../include \
		  -I./ \
		  -I./wrapper/inc \
		  -I./osa/inc

ifeq ($(SST_DBG), Y)
ACFLAGS += -g -DCONFIG_SST_DBG
endif

ifeq ($(SST_MIGRATION), Y)
ACFLAGS += -DCONFIG_SST_MIGRATION=1
endif

ifeq ($(DATA_MIGRATION), Y)
ACFLAGS += -DCONFIG_DATA_MIGRATION=1
endif

ifeq ($(ID2_SUPPORT), Y)
ACFLAGS += -DCONFIG_ID2_SUPPORT=1
endif

LIB_SRCS += $(LOCAL_DIR)/osa/linux/sst_osa.c \
        $(LOCAL_DIR)/wrapper/km/sst_wrapper.c \
        $(LOCAL_DIR)/sst.c

LIB_OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(LIB_SRCS)))
TEST_OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(TEST_SRCS)))

all: $(LIBS)
%.o: %.c
	$(CC) -c $(CFLAGS) $(ACFLAGS) $< -o $*.o

$(LIBS): $(LIB_OBJS)
	$(AR) rc $(LIBS) $(LIB_OBJS)
install :
	cp libsst.a ${BUILDROOT}/${BUILDOUTPUT}/lib
clean:
	rm -f $(LIB_OBJS) $(LIBS)

