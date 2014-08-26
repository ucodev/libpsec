CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=generic.o nop.o
INCLUDEDIRS=-I../../../include

all:
	@/bin/sh -c 'if [ -e ../../../.lgmp ]; then make all_good; else make all_nop; fi'

all_good:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c

all_nop:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c nop.c

clean:
	rm -f ${OBJS}
