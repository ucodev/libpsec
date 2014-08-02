CC=`cat ../../../../.compiler`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=generic.o hmac.o sha1.o sha224-256.o sha384-512.o usha.o
INCLUDEDIRS=-I../include

all:
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c hmac.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c sha1.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c sha224-256.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c sha384-512.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c usha.c

clean:
	rm -f ${OBJS}
