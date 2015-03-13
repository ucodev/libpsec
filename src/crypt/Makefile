CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=ld
CCFLAGS=-g -O2 -Wall -Werror -fPIC
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./aes/*.o ./blowfish/*.o ./chacha/*.o ./otp/*.o ./salsa/*.o
OBJS=generic.o
TARGET=crypt.o

all:
	cd aes && make && cd ..
	cd blowfish && make && cd ..
	cd chacha && make && cd ..
	cd otp && make && cd ..
	cd salsa && make && cd ..
	${CC} ${DEFINES} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd aes && make clean && cd ..
	cd blowfish && make clean && cd ..
	cd chacha && make clean && cd ..
	cd otp && make clean && cd ..
	cd salsa && make clean && cd ..
	rm -f ${OBJS} ${TARGET}
