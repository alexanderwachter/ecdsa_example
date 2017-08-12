EXEC_NAME=ecdsa
CC=gcc
CXX=g++
RM=rm -f
CPPFLAGS=-g -Wall
LDFLAGS=-g 
LDLIBS=-lssl -lcrypto

SRCDIR=.
SRCS=$(wildcard $(SRCDIR)/*.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))

all: $(EXEC_NAME)

$(EXEC_NAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $(EXEC_NAME) $(OBJS) $(LDLIBS)

depend: .depend

.depend: $(SRCS)
	$(RM) ./.depend
	$(CC) $(CPPFLAGS) -MM $^ >> ./.depend;

.PHONY: clean
clean:
	$(RM) $(OBJS) $(EXEC_NAME)

distclean: clean
	$(RM) *~ .depend

-include .depend
