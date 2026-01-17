CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lcrypto

OBJS_SERVER = server.o crypto_utils.o
OBJS_CLIENT = client.o crypto_utils.o

all: server client
server: $(OBJS_SERVER)
	$(CC) $(CFLAGS) -o server $(OBJS_SERVER) $(LDFLAGS)

client: $(OBJS_CLIENT)
	$(CC) $(CFLAGS) -o client $(OBJS_CLIENT) $(LDFLAGS)

server.o: server.c common.h crypto_utils.h
client.o: client.c common.h crypto_utils.h
crypto_utils.o: crypto_utils.c crypto_utils.h

clean:
	rm -f server client *.o
