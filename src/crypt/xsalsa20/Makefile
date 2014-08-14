CC=`cat ../../../.compiler`
DEFINES=`cat ../../../.defines`
CCFLAGS=-g -O2 -Wall -Werror -fPIC
OBJS=generic.o hsalsa20_core.o poly1305_auth.o poly1305_verify.o salsa20.o salsa20_core.o salsa20_xor.o secretbox.o verify_16.o xsalsa20.o xsalsa20_xor.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c hsalsa20_core.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c poly1305_auth.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c poly1305_verify.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c salsa20.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c salsa20_core.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c salsa20_xor.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c secretbox.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c verify_16.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c xsalsa20.c
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c xsalsa20_xor.c

clean:
	rm -f ${OBJS}

