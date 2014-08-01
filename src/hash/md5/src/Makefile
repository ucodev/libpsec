CC=`cat ../../../../.compiler`
CCFLAGS=-O2 -Wall -Werror -fPIC
OBJS=generic.o md5c.o
INCLUDEDIRS=-I../include

all:
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c md5c.c

clean:
	rm -f ${OBJS}
