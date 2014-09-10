CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=/usr/bin/ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
INCLUDEDIRS=-I../../include
OBJS_COMMON=./aes/*.o ./blowfish/*.o ./chacha/*.o ./otp/*.o ./xsalsa/*.o
OBJS=generic.o
TARGET=crypt.o

all:
	make -C aes/
	make -C blowfish/
	make -C chacha/
	make -C otp/
	make -C xsalsa/
	${CC} ${DEFINES} ${CCFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	make -C aes/ clean
	make -C blowfish/ clean
	make -C chacha/ clean
	make -C otp/ clean
	make -C xsalsa/ clean
	rm -f ${OBJS} ${TARGET}
