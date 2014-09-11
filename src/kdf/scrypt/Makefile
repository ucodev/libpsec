CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -std=c99 -pedantic -O2 -Wall -Werror -fPIC
OBJS=generic.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c

clean:
	rm -f ${OBJS}
