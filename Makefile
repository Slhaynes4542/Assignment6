#
# Makefile for TLS-enabled chat client, server, and directory server
#
CC	= gcc
EXECUTABLES=chatClient5 chatServer5 directoryServer5
INCLUDES= $(wildcard *.h)
SOURCES = $(wildcard *.c)
DEPS	= $(INCLUDES)
OBJECTS = $(SOURCES:.c=.o)
LDFLAGS =
CFLAGS	= -g -ggdb -std=c99 -Wc++-compat -Wmain \
		-Wignored-qualifiers -Wshift-negative-value \
		-Wunused -Wunused-macros -Wunused-but-set-parameter \
		-Wformat -Wformat-nonliteral -Wuninitialized \
		-Wformat-y2k -Wswitch-default -Wfatal-errors
#CFLAGS += -ggdb3
#CFLAGS += -Wc99-c11-compat -Wformat-truncation=2 -Wformat-overflow -Wformat-signedness

# Uncomment the LIBS line below containing the library that you're using
#LIBS	= -lcrypto -lgnutls
LIBS	+= -lcrypto -lssl

all:	tls

tls:	$(EXECUTABLES)

chatClient5: chatClient5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LIBS)

chatServer5: chatServer5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LIBS)

directoryServer5: directoryServer5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LIBS)


# Clean up the mess we made
.PHONY: clean
clean:
	@-rm -f $(OBJECTS) $(EXECUTABLES)
