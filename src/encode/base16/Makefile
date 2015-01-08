CC=`cat ../../../.compiler`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
ARCHFLAGS=`cat ../../../.archflags`
OBJS=generic.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c

clean:
	rm -f ${OBJS}
