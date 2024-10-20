# Paths
INC_DIR_GAZELLE = ../../src/lstack/include/public_api/
LIB_DIR_GAZELLE = ../../src/lstack
INC_DIR_LOCAL = ./inc

# Compiler and flags
CC = gcc
CFLAGS = -g -lpthread -I$(INC_DIR_LOCAL) -I$(INC_DIR_GAZELLE)
LDFLAGS = -L$(LIB_DIR_GAZELLE) -llstack
# Targets
all: client server

client: src/client.c
	$(CC) src/client.c -o client $(CFLAGS) -lm

server: src/server.c
	$(CC) src/server.c -o server $(CFLAGS) $(LDFLAGS)

# Clean up
clean:
	rm -f client server
