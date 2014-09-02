CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=generic.o low_128.o low_160.o rmd128.o rmd160.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c low_128.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c low_160.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c rmd128.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c rmd160.c

clean:
	rm -f ${OBJS}
