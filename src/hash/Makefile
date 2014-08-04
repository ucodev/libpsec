CC=`cat ../../.compiler`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
INCLUDEDIRS=-I../../include
OBJS_COMMON=./md4/*.o ./md5/*.o ./sha/*.o
OBJS=generic.o low.o
TARGET=hash.o

all:
	make -C md4/
	make -C md5/
	make -C sha/
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c low.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C md4/ clean
	make -C md5/ clean
	make -C sha/ clean
	rm -f ${OBJS} ${TARGET}
