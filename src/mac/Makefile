CC=`cat ../../.compiler`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
INCLUDEDIRS=-I../../include
OBJS_COMMON=./hmac/*.o
OBJS=generic.o
TARGET=mac.o

all:
	make -C hmac/
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C hmac/ clean
	rm -f ${OBJS} ${TARGET}
