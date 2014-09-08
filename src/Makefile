CC=`cat ../.compiler`
CCFLAGS=
LDFLAGS=-shared
OBJS=arch/arch.o auth/auth.o crypt/crypt.o decode/decode.o encode/encode.o generate/generate.o hash/hash.o kdf/kdf.o ke/ke.o mac/mac.o tc/tc.o
TARGET=libpsec.so

all:
	make -C arch/
	make -C auth/
	make -C crypt/
	make -C decode/
	make -C encode/
	make -C generate/
	make -C hash/
	make -C kdf/
	make -C ke/
	make -C mac/
	make -C tc/
	${CC} -o ${TARGET} ${OBJS} ${LDFLAGS}

clean:
	make -C arch/ clean
	make -C auth/ clean
	make -C crypt/ clean
	make -C decode/ clean
	make -C encode/ clean
	make -C generate/ clean
	make -C hash/ clean
	make -C kdf/ clean
	make -C ke/ clean
	make -C mac/ clean
	make -C tc/ clean
	rm -f ${TARGET}

