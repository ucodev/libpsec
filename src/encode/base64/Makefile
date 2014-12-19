CC=`cat ../../../.compiler`
CCFLAGS=-g -O2 -Wall -fPIC
OBJS=generic.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c

clean:
	rm -f ${OBJS}
