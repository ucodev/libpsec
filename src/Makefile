CC=`cat ../.compiler`
CCFLAGS=
LDFLAGS=-shared
ELFLAGS=`cat ../.elflags`
OBJS=arch/arch.o auth/auth.o crypt/crypt.o decode/decode.o encode/encode.o generate/generate.o hash/hash.o kdf/kdf.o ke/ke.o mac/mac.o tc/tc.o
TARGET=libpsec.so

all:
	cd arch && make && cd ..
	cd auth && make && cd ..
	cd crypt && make && cd ..
	cd decode && make && cd ..
	cd encode && make && cd ..
	cd generate && make && cd ..
	cd hash && make && cd ..
	cd kdf && make && cd ..
	cd ke && make && cd ..
	cd mac && make && cd ..
	cd tc && make && cd ..
	${CC} -o ${TARGET} ${OBJS} ${LDFLAGS} ${ELFLAGS}

clean:
	cd arch && make clean && cd ..
	cd auth && make clean && cd ..
	cd crypt && make clean && cd ..
	cd decode && make clean && cd ..
	cd encode && make clean && cd ..
	cd generate && make clean && cd ..
	cd hash && make clean && cd ..
	cd kdf && make clean && cd ..
	cd ke && make clean && cd ..
	cd mac && make clean && cd ..
	cd tc && make clean && cd ..
	rm -f ${TARGET}

