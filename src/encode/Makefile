CC=`cat ../../.compiler`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS_COMMON=./base64/src/*.o
OBJS=generic.o
TARGET=encode.o

all:
	make -C base64/
	${CC} ${CCFLAGS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C base64/ clean
	rm -f ${OBJS} ${TARGET}
