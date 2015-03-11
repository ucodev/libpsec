CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=/usr/bin/ld
CCFLAGS=-g -std=c99 -fstrict-aliasing -pedantic -O2 -Wall -Werror -fPIC
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./mem/*.o ./spec/*.o
OBJS=generic.o
TARGET=arch.o

all:
	cd mem && make && cd ..
	cd spec && make && cd ..
	${CC} ${DEFINES} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd mem && make clean && cd ..
	cd spec && make clean && cd ..
	rm -f ${OBJS} ${TARGET}
