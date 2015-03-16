CC=`cat ../../../.compiler`
CCFLAGS=
ECFLAGS=`cat ../../../.ecflags`
ARCHFLAGS=`cat ../../../.archflags`
OBJS=generic.o oaes_lib.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c oaes_lib.c

clean:
	rm -f ${OBJS}

