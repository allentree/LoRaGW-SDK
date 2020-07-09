TARGET = sshd_agent

CC = gcc

SRCS += ./../../connectivity/rd_net.c ./../../connectivity/ws_nopoll.c ./sshd_agent.c

CFLAGS += -I./../../connectivity -I./../../connectivity/include -I./../../connectivity/include/nopoll

LDFLAGS += -L./../../connectivity/libs -lssl -lcrypto -lz -lpthread

$(TARGET): 
	$(CC) -o $(TARGET) $(SRCS) ./../../connectivity/libs/libnopoll.a $(LDFLAGS) $(CFLAGS)
	rm -f *.o

clean:
	rm -rf *.o $(TARGET)
