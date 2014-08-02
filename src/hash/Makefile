CC=`cat ../../.compiler`
LD=/usr/bin/ld
CCFLAGS=-O2 -Wall -Werror -fPIC
OBJS_COMMON=./md5/src/*.o ./sha/src/*.o
OBJS=format.o generic.o
TARGET=hash.o

all:
	make -C md5/
	make -C sha/
	${CC} ${CCFLAGS} -c format.c
	${CC} ${CCFLAGS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C md5/ clean
	make -C sha/ clean
	rm -f ${OBJS} ${TARGET}
