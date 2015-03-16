CC=`cat ../../../.compiler`
CCFLAGS=
ECFLAGS=`cat ../../../.ecflags`
ARCHFLAGS=`cat ../../../.archflags`
OBJS=generic.o poly1305_auth.o poly1305_verify.o verify_16.o
INCLUDEDIRS=-I../../../include

all:
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c poly1305_auth.c
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c poly1305_verify.c
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c verify_16.c

clean:
	rm -f ${OBJS}
