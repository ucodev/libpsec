CC=`cat ../../.compiler`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS_COMMON=
OBJS=generic.o
TARGET=hmac.o

all:
	${CC} ${CCFLAGS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	rm -f ${OBJS} ${TARGET}
