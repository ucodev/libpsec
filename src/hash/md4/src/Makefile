CC=`cat ../../../../.compiler`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=generic.o md4c.o
INCLUDEDIRS=-I../include

all:
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c md4c.c

clean:
	rm -f ${OBJS}
