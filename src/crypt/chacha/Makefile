CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=generic.o chacha_core.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c chacha_core.c

clean:
	rm -f ${OBJS}

