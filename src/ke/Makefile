CC=`cat ../../.compiler`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
INCLUDEDIRS=-I../../include
OBJS_COMMON=./dh/*.o
OBJS=generic.o
TARGET=ke.o

all:
	make -C dh/
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C dh/ clean
	rm -f ${OBJS} ${TARGET}
