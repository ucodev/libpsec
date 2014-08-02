CC=`cat ../.compiler`
CCFLAGS=
LDFLAGS=-shared
OBJS=hash/hash.o hmac/hmac.o kdf/kdf.o
TARGET=libpsec.so

all:
	make -C hash/
	make -C hmac/
	make -C kdf/
	${CC} -o ${TARGET} ${OBJS} ${LDFLAGS}

clean:
	make -C hash/ clean
	make -C hmac/ clean
	make -C kdf/ clean
	rm -f ${TARGET}

