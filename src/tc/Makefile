CC=`cat ../../.compiler`
LD=`cat ../../.olinker`
CCFLAGS=-O0
ECFLAGS=`cat ../../.ecflags`
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./mem/*.o
OBJS=generic.o
TARGET=tc.o

all:
	cd mem && make && cd ..
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd mem && make clean && cd ..
	rm -f ${OBJS} ${TARGET}
