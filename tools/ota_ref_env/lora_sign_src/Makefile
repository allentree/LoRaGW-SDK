.PHONY: all

CFLAGS  = -std=gnu99 -Wall -g
LDFLAGS = 


LDFLAGS += -lm -pthread -lrt
LDFLAGS += -ldl -lssl -lcrypto


INCLUD_PATH += -I./


SRC_FILE =  ./ecdsa_operation.c

SRC_FILE += ./lora_sign_test.c

TARGET = lora_sign


all:
	
	gcc $(CFLAGS) $(INCLUD_PATH) -o $(TARGET) $(SRC_FILE) $(LDFLAGS)
clean:
	 rm -rf $(TARGET) *.o
