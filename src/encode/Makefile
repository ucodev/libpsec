CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -fPIC
INCLUDEDIRS=-I../../include
OBJS_COMMON=./base16/*.o ./base64/*.o
OBJS=generic.o
TARGET=encode.o

all:
	make -C base16/
	make -C base64/
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C base16/ clean
	make -C base64/ clean
	rm -f ${OBJS} ${TARGET}
