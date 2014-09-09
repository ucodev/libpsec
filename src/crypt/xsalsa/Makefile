CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=generic.o hsalsa_core.o salsa.o salsa_core.o salsa_xor.o secretbox.o xsalsa.o xsalsa_xor.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c hsalsa_core.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c salsa.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c salsa_core.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c salsa_xor.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c secretbox.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c xsalsa.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c xsalsa_xor.c

clean:
	rm -f ${OBJS}

