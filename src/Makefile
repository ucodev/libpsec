CC=`cat ../.compiler`
CCFLAGS=
LDFLAGS=-shared
OBJS=crypt/crypt.o decode/decode.o encode/encode.o generate/generate.o hash/hash.o kdf/kdf.o ke/ke.o mac/mac.o
TARGET=libpsec.so

all:
	make -C crypt/
	make -C decode/
	make -C encode/
	make -C generate/
	make -C hash/
	make -C kdf/
	make -C ke/
	make -C mac/
	${CC} -o ${TARGET} ${OBJS} ${LDFLAGS}

clean:
	make -C crypt/ clean
	make -C decode/ clean
	make -C encode/ clean
	make -C generate/ clean
	make -C hash/ clean
	make -C kdf/ clean
	make -C ke/ clean
	make -C mac/ clean
	rm -f ${TARGET}

