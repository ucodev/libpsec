CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=curve25519.o generic.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c curve25519.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c

clean:
	rm -f ${OBJS}
