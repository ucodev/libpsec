CC=`cat ../../../.compiler`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=generic.o hsalsa20_core.o poly1305_auth.o poly1305_verify.o salsa20.o salsa20_core.o salsa20_xor.o secretbox.o verify_16.o xsalsa20.o xsalsa20_xor.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c hsalsa20_core.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c poly1305_auth.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c poly1305_verify.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c salsa20.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c salsa20_core.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c salsa20_xor.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c secretbox.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c verify_16.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c xsalsa20.c
	${CC} ${CCFLAGS} ${INCLUDEDIRS} -c xsalsa20_xor.c

clean:
	rm -f ${OBJS}

