CC=`cat ../../../.compiler`
CCFLAGS=
ECFLAGS=`cat ../../../.ecflags`
ARCHFLAGS=`cat ../../../.archflags`
OBJS=generic.o nop.o
#INCLUDEDIRS=-I../../../include

all:
	@/bin/sh -c 'if [ -e ../../../.lcrypt ]; then make all_good; else make all_nop; fi'

all_good:
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c

all_nop:
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c nop.c

clean:
	rm -f ${OBJS}
