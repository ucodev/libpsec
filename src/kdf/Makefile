CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=/usr/bin/ld
CCFLAGS=-g -std=c99 -O2 -Wall -Werror -fPIC
INCLUDEDIRS=-I../../include
OBJS_COMMON=./pbkdf1/*.o ./pbkdf2/*.o
OBJS=generic.o
TARGET=kdf.o

all:
	make -C pbkdf1/
	make -C pbkdf2/
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C pbkdf1/ clean
	make -C pbkdf2/ clean
	rm -f ${OBJS} ${TARGET}
