CC = gcc
CFLAGS = -Wall -O2
OBJS=pcap.o analyze.o checksum.o print.o
SRCS=$(OBJS:%.o=%.c)
LDLIBS=
TARGET=pcap
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

clean: 
	rm $(OBJS) $(TARGET)