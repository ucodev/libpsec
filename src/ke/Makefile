CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./chreke/*.o ./dh/*.o ./dheke/*.o ./ecdh/*.o
OBJS=generic.o
TARGET=ke.o

all:
	make -C chreke/
	make -C dh/
	make -C dheke/
	make -C ecdh/
	${CC} ${DEFINES} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C chreke/ clean
	make -C dh/ clean
	make -C dheke/ clean
	make -C ecdh/ clean
	rm -f ${OBJS} ${TARGET}
