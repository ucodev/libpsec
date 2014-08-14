CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=blake2b-ref.o blake2s-ref.o generic.o low.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c blake2b-ref.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c blake2s-ref.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c low.c

clean:
	rm -f ${OBJS}
