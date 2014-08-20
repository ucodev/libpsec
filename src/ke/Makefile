CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
INCLUDEDIRS=-I../../include
OBJS_COMMON=./dh/*.o ./pankake/*.o
OBJS=generic.o
TARGET=ke.o

all:
	make -C dh/
	make -C pankake/
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C dh/ clean
	make -C pankake/ clean
	rm -f ${OBJS} ${TARGET}
