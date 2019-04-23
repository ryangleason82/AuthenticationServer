#
# File          : Makefile
# Description   : Build file for CMPSC497 project 1, applied cryptography
#                 


# Environment Setup
#LIBDIRS=-L. -L/opt/local/lib
#INCLUDES=-I. -I/opt/local/include
CC=gcc 
CFLAGS=-c $(INCLUDES) -g -Wall 
LINK=gcc -g
LDFLAGS=$(LIBDIRS)
AR=ar rc
RANLIB=ranlib

# Suffix rules
.c.o :
	${CC} ${CFLAGS} $< -o $@

#
# Setup builds

TARGETS=cmpsc497-p4
LIBS=-lcrypto -lm

#
# Project Protections

p4 : $(TARGETS)

cmpsc497-p4 : cmpsc497-main.o cmpsc497-kvs.o cmpsc497-ssl.o cmpsc497-util.o cmpsc497-ops-8.o
	$(LINK) $(LDFLAGS) cmpsc497-main.o cmpsc497-kvs.o cmpsc497-ssl.o cmpsc497-util.o cmpsc497-ops-8.o $(LIBS) -o $@

clean:
	rm -f *.o *~ $(TARGETS)

BASENAME=p4
tar: 
	tar cvfz $(BASENAME).tgz -C ..\
	    $(BASENAME)/Makefile \
            $(BASENAME)/cmpsc497-main.c \
            $(BASENAME)/cmpsc497-format-8.h \
            $(BASENAME)/cmpsc497-ops-8.c \
	    $(BASENAME)/cmpsc497-kvs.c \
	    $(BASENAME)/cmpsc497-kvs.h \
	    $(BASENAME)/cmpsc497-ssl.c \
	    $(BASENAME)/cmpsc497-ssl.h \
	    $(BASENAME)/cmpsc497-util.c \
	    $(BASENAME)/cmpsc497-util.h \
