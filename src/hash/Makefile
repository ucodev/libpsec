CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./blake/*.o ./blake2/*.o ./gost/*.o ./haval/*.o ./md2/*.o ./md4/*.o ./md5/*.o ./ripemd/*.o ./sha/*.o ./tiger/*.o ./whirlpool/*.o
OBJS=generic.o low.o
TARGET=hash.o

all:
	make -C blake/
	make -C blake2/
	make -C gost/
	make -C haval/
	make -C md2/
	make -C md4/
	make -C md5/
	make -C ripemd/
	make -C sha/
	make -C tiger/
	make -C whirlpool/
	${CC} ${DEFINES} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${DEFINES} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c low.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C blake/ clean
	make -C blake2/ clean
	make -C gost/ clean
	make -C haval/ clean
	make -C md2/ clean
	make -C md4/ clean
	make -C md5/ clean
	make -C ripemd/ clean
	make -C sha/ clean
	make -C tiger/ clean
	make -C whirlpool/ clean
	rm -f ${OBJS} ${TARGET}

