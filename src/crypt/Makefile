CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
INCLUDEDIRS=-I../../include
OBJS_COMMON=./otp/*.o ./xsalsa20/*.o
OBJS=generic.o
TARGET=crypt.o

all:
	make -C otp/
	make -C xsalsa20/
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C otp/ clean
	make -C xsalsa20/ clean
	rm -f ${OBJS} ${TARGET}
