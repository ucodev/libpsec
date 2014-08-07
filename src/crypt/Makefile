CC=`cat ../../.compiler`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
INCLUDEDIRS=-I../../include
OBJS_COMMON=./xsalsa20/*.o
OBJS=generic.o
TARGET=crypt.o

all:
	make -C xsalsa20/
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C xsalsa20/ clean
	rm -f ${OBJS} ${TARGET}
