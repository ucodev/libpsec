CC=`cat ../../../.compiler`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=blake2b-ref.o blake2s-ref.o generic.o low.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c blake2b-ref.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c blake2s-ref.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c low.c

clean:
	rm -f ${OBJS}
