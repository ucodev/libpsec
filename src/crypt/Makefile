CC=`cat ../../.compiler`
LD=`cat ../../.olinker`
CCFLAGS=
ECFLAGS=`cat ../../.ecflags`
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
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd aes && make clean && cd ..
	cd blowfish && make clean && cd ..
	cd chacha && make clean && cd ..
	cd otp && make clean && cd ..
	cd salsa && make clean && cd ..
	rm -f ${OBJS} ${TARGET}

