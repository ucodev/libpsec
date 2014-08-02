CC=`cat ../../.compiler`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS_COMMON=./pbkdf2/src/*.o
OBJS=generic.o
TARGET=kdf.o

all:
	make -C pbkdf2/
	${CC} ${CCFLAGS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C pbkdf2/ clean
	rm -f ${OBJS} ${TARGET}
