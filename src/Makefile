CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

CLNT_OBJS = client.o
SERV_OBJS = server.o
OBJS = $(CLNT_OBJS) $(SERV_OBJS) 

BINS = client server

CFLAGS = -I../include -I../libraries/openssl-3.3.0-lib/include -I../libraries/wolfssl-5.7.0-lib/include
LDFLAGS = -L../libraries/openssl-3.3.0-lib/lib64 -L../libraries/wolfssl-5.7.0-lib/lib -lcrypto -lssl -lwolfssl -lpthread

.PHONY: all
all: client server

client: $(CLNT_OBJS)
	$(CC) -o $@ $(CLNT_OBJS) $(LDFLAGS)
	cp $@ ../apps

server: $(SERV_OBJS)
	$(CC) -o $@ $(SERV_OBJS) $(LDFLAGS)
	cp $@ ../apps

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINS) 
