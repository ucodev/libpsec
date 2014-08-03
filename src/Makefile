CC=`cat ../.compiler`
CCFLAGS=
LDFLAGS=-shared
OBJS=hash/hash.o kdf/kdf.o mac/mac.o
TARGET=libpsec.so

all:
	make -C hash/
	make -C kdf/
	make -C mac/
	${CC} -o ${TARGET} ${OBJS} ${LDFLAGS}

clean:
	make -C hash/ clean
	make -C kdf/ clean
	make -C mac/ clean
	rm -f ${TARGET}

