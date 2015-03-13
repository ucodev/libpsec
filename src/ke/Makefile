CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./chreke/*.o ./dh/*.o ./dheke/*.o ./ecdh/*.o
OBJS=generic.o
TARGET=ke.o

all:
	cd chreke && make && cd ..
	cd dh && make && cd ..
	cd dheke && make && cd ..
	cd ecdh && make && cd ..
	${CC} ${DEFINES} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd chreke && make clean && cd ..
	cd dh && make clean && cd ..
	cd dheke && make clean && cd ..
	cd ecdh && make clean && cd ..
	rm -f ${OBJS} ${TARGET}
