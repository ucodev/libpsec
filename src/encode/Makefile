CC=`cat ../../.compiler`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
INCLUDEDIRS=-I../../include
OBJS_COMMON=./base64/*.o
OBJS=generic.o
TARGET=encode.o

all:
	make -C base64/
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C base64/ clean
	rm -f ${OBJS} ${TARGET}
