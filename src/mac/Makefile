CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./hmac/*.o ./poly1305/*.o
OBJS=generic.o
TARGET=mac.o

all:
	cd hmac && make && cd ..
	cd poly1305 && make && cd ..
	${CC} ${DEFINES} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd hmac && make clean && cd ..
	cd poly1305 && make clean && cd ..
	rm -f ${OBJS} ${TARGET}
