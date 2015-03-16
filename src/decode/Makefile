CC=`cat ../../.compiler`
LD=`cat ../../.olinker`
CCFLAGS=
ECFLAGS=`cat ../../.ecflags`
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./base16/*.o ./base64/*.o
OBJS=generic.o
TARGET=decode.o

all:
	cd base16 && make && cd ..
	cd base64 && make && cd ..
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd base16 && make clean && cd ..
	cd base64 && make clean && cd ..
	rm -f ${OBJS} ${TARGET}
