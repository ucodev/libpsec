CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=ld
CCFLAGS=-g -O2 -Wall -fPIC
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./base16/*.o ./base64/*.o
OBJS=generic.o
TARGET=decode.o

all:
	cd base16 && make && cd ..
	cd base64 && make && cd ..
	${CC} ${DEFINES} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd base16 && make clean && cd ..
	cd base64 && make clean && cd ..
	rm -f ${OBJS} ${TARGET}
