CC=`cat ../../.compiler`
LD=`cat ../../.olinker`
CCFLAGS=
ECFLAGS=`cat ../../.ecflags`
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./blake/*.o ./blake2/*.o ./gost/*.o ./haval/*.o ./md2/*.o ./md4/*.o ./md5/*.o ./ripemd/*.o ./sha/*.o ./tiger/*.o ./whirlpool/*.o
OBJS=generic.o low.o
TARGET=hash.o

all:
	cd blake && make && cd ..
	cd blake2 && make && cd ..
	cd gost && make && cd ..
	cd haval && make && cd ..
	cd md2 && make && cd ..
	cd md4 && make && cd ..
	cd md5 && make && cd ..
	cd ripemd && make && cd ..
	cd sha && make && cd ..
	cd tiger && make && cd ..
	cd whirlpool && make && cd ..
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${CC} ${ECFLAGS} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c low.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd blake && make clean && cd ..
	cd blake2 && make clean && cd ..
	cd gost && make clean && cd ..
	cd haval && make clean && cd ..
	cd md2 && make clean && cd ..
	cd md4 && make clean && cd ..
	cd md5 && make clean && cd ..
	cd ripemd && make clean && cd ..
	cd sha && make clean && cd ..
	cd tiger && make clean && cd ..
	cd whirlpool && make clean && cd ..
	rm -f ${OBJS} ${TARGET}

