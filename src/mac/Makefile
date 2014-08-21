CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
INCLUDEDIRS=-I../../include
OBJS_COMMON=./hmac/*.o ./poly1305/*.o
OBJS=generic.o
TARGET=mac.o

all:
	make -C hmac/
	make -C poly1305/ 
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C hmac/ clean
	make -C poly1305/ clean
	rm -f ${OBJS} ${TARGET}
