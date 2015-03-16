CC=`cat ../../../.compiler`
CCFLAGS=
ECFLAGS=`cat ../../../.ecflags`
OBJS=generic.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${ECFLAGS} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c

clean:
	rm -f ${OBJS}
