CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -std=c99 -O2 -Wall -Werror -fPIC
OBJS=blake224.o blake256.o blake384.o blake512.o generic.o low.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c blake224.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c blake256.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c blake384.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c blake512.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c low.c

clean:
	rm -f ${OBJS}
