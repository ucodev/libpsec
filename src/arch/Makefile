CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=/usr/bin/ld
CCFLAGS=-g -std=c99 -fstrict-aliasing -pedantic -O2 -Wall -Werror -fPIC
INCLUDEDIRS=-I../../include
OBJS_COMMON=./mem/*.o
OBJS=generic.o
TARGET=arch.o

all:
	make -C mem/
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C mem/ clean
	rm -f ${OBJS} ${TARGET}
