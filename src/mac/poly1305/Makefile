CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=generic.o poly1305_auth.o poly1305_verify.o verify_16.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c poly1305_auth.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c poly1305_verify.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c verify_16.c

clean:
	rm -f ${OBJS}
