CC=`cat ../../../.compiler`
CCFLAGS=
ECFLAGS=`cat ../../../.ecflags`
ARCHFLAGS=`cat ../../../.archflags`
OBJS=blake224.o blake256.o blake384.o blake512.o generic.o low.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c blake224.c
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c blake256.c
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c blake384.c
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c blake512.c
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c low.c

clean:
	rm -f ${OBJS}
