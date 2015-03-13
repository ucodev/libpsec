CC=`cat ../../.compiler`
DEFINES=`cat ../../.defines`
LD=ld
CCFLAGS=-g -std=c99 -O2 -Wall -Werror -fPIC
ARCHFLAGS=`cat ../../.archflags`
INCLUDEDIRS=-I../../include
OBJS_COMMON=./bcrypt/*.o ./hkdf/*.o ./pbkdf1/*.o ./pbkdf2/*.o ./scrypt/*.o
OBJS=generic.o
TARGET=kdf.o

all:
	cd bcrypt && make && cd ..
	cd hkdf && make && cd ..
	cd pbkdf1 && make && cd ..
	cd pbkdf2 && make && cd ..
	cd scrypt && make && cd ..
	${CC} ${DEFINES} ${CCFLAGS} ${ARCHFLAGS} ${INCLUDEDIRS} -c generic.c
	${LD} -r ${OBJS_COMMON} ${OBJS} -o ${TARGET}

clean:
	cd bcrypt && make clean && cd ..
	cd hkdf && make clean && cd ..
	cd pbkdf1 && make clean && cd ..
	cd pbkdf2 && make clean && cd ..
	cd scrypt && make clean && cd ..
	rm -f ${OBJS} ${TARGET}
