CC=`cat ../.compiler`
CCFLAGS=
LDFLAGS=-shared
OBJS=decode/decode.o encode/encode.o hash/hash.o kdf/kdf.o mac/mac.o
TARGET=libpsec.so

all:
	make -C decode/
	make -C encode/
	make -C hash/
	make -C kdf/
	make -C mac/
	${CC} -o ${TARGET} ${OBJS} ${LDFLAGS}

clean:
	make -C decode/ clean
	make -C encode/ clean
	make -C hash/ clean
	make -C kdf/ clean
	make -C mac/ clean
	rm -f ${TARGET}

