CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=ld
CCFLAGS=-g -O0 -Wall -Werror -fPIC
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./mem/*.o
OBJS=generic.o
TARGET=tc.o

all:
	cd mem && make && cd ..
	${CC} ${DEFINES} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd mem && make clean && cd ..
	rm -f ${OBJS} ${TARGET}
