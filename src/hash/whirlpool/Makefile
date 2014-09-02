CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=generic.o low.o whirlpool.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c low.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c whirlpool.c

clean:
	rm -f ${OBJS}
