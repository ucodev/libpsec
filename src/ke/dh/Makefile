CC=`cat ../../../.compiler`
CCFLAGS=
ECFLAGS=`cat ../../../.ecflags`
ARCHFLAGS=`cat ../../../.archflags`
OBJS=generic.o nop.o
INCLUDEDIRS=-I../../../include

all:
	@/tmp/uconfsh -c 'if [ -e ../../../.lgmp ]; then make all_good; else make all_nop; fi'

all_good:
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c

all_nop:
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c nop.c

clean:
	rm -f ${OBJS}
