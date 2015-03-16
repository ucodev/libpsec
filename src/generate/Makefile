CC=`cat ../../.compiler`
LD=`cat ../../.olinker`
CCFLAGS=
ECFLAGS=`cat ../../.ecflags`
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./random/*.o
OBJS=generic.o
TARGET=generate.o

all:
	cd random && make && cd ..
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd random && make clean && cd ..
	rm -f ${OBJS} ${TARGET}
