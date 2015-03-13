CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./shadow/*.o
OBJS=generic.o
TARGET=auth.o

all:
	cd shadow && make && cd ..
	${CC} ${DEFINES} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd shadow && make clean && cd ..
	rm -f ${OBJS} ${TARGET}
