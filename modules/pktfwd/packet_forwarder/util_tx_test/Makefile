### Application-specific constants

APP_NAME := util_tx_test

### Constant symbols

ifeq ($(TOOLCHAIN_SYSROOT),)
CC := $(CROSS_COMPILE)gcc
else
CC := $(CROSS_COMPILE)gcc --sysroot=${TOOLCHAIN_SYSROOT}
endif
AR := $(CROSS_COMPILE)ar

CFLAGS := -O2 -Wall -Wextra -std=c99 -Iinc -I.

OBJDIR = obj
INCLUDES = $(wildcard inc/*.h)

### General build targets

all: $(APP_NAME)

clean:
	rm -f $(OBJDIR)/*.o
	rm -f $(APP_NAME)

### Sub-modules compilation

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c $(INCLUDES) | $(OBJDIR)
	$(CC) -c $(CFLAGS) $< -o $@

### Main program assembly

$(APP_NAME): $(OBJDIR)/$(APP_NAME).o  $(OBJDIR)/base64.o
	$(CC) $< $(OBJDIR)/base64.o -o $@

### EOF
