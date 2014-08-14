CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=generic.o hmac.o low.o sha1.o sha224-256.o sha384-512.o usha.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c hmac.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c low.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c sha1.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c sha224-256.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c sha384-512.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c usha.c

clean:
	rm -f ${OBJS}
