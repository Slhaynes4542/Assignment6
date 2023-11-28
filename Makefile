#
# Makefile for chat server
#
# LIBS	= -lsocket -lnsl
CC	= gcc
EXECUTABLES=chatClient1 chatServer1 chatClient2 chatServer5 directoryServer2
INCLUDES= $(wildcard *.h)
SOURCES = $(wildcard *.c)
DEPS	= $(INCLUDES)
OBJECTS = $(SOURCES:.c=.o)
OBJECTS  += $(SOURCES:.c=.dSYM)
LIBS	=
LDFLAGS =
CFLAGS	= -g -ggdb -std=c99 -Wc++-compat -Wmain \
		-Wignored-qualifiers -Wshift-negative-value \
		-Wunused -Wunused-macros -Wunused-but-set-parameter \
		-Wformat -Wformat-nonliteral -Wuninitialized \
		-Wformat-y2k -Wswitch-default -Wfatal-errors
#CFLAGS += -ggdb3
#CFLAGS += -Wc99-c11-compat -Wformat-truncation=2 -Wformat-overflow -Wformat-signedness

all:    chat2

chat2:	chatClient2 chatServer5 directoryServer2


chatClient1: chatClient1.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $<

chatServer1: chatServer1.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $<

chatClient2: chatClient2.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $< -lssl -lcrypto

chatServer5: chatServer5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $< -lssl -lcrypto

directoryServer2: directoryServer2.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $< -lssl -lcrypto


# Clean up the mess we made
.PHONY: clean
clean:
	@-rm -rf $(OBJECTS) $(EXECUTABLES)
