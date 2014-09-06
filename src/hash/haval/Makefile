CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -std=c99 -pedantic -O2 -Wall -Werror -fPIC
OBJS=generic.o haval.o low.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c haval.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c low.c

clean:
	rm -f ${OBJS}
