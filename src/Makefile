CC=`cat ../.compiler`
CCFLAGS=
LDFLAGS=-shared
OBJS=hash/hash.o
TARGET=libpsec.so

all:
	make -C hash/
	${CC} -o ${TARGET} ${OBJS} ${LDFLAGS}

clean:
	make -C hash/ clean
	rm -f ${TARGET}

