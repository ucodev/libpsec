CC=`cat ../.compiler`
LDFLAGS=-lpsec

all:
	${CC} -o base16_decode base16_decode.c ${LDFLAGS}
	${CC} -o base16_encode base16_encode.c ${LDFLAGS}
	${CC} -o base64_decode base64_decode.c ${LDFLAGS}
	${CC} -o base64_encode base64_encode.c ${LDFLAGS}
	${CC} -o blake2b_buffer blake2b_buffer.c ${LDFLAGS}
	${CC} -o blake2s_buffer blake2s_buffer.c ${LDFLAGS}
	${CC} -o blake2s_file blake2s_file.c ${LDFLAGS}
	${CC} -o hmac_md5 hmac_md5.c ${LDFLAGS}
	${CC} -o md5_buffer_alloc md5_buffer_alloc.c ${LDFLAGS}
	${CC} -o md5_buffer md5_buffer.c ${LDFLAGS}
	${CC} -o md5_file_alloc md5_file_alloc.c ${LDFLAGS}
	${CC} -o md5_file md5_file.c ${LDFLAGS}
	${CC} -o pbkdf2_alloc pbkdf2_alloc.c ${LDFLAGS}
	${CC} -o pbkdf2 pbkdf2.c ${LDFLAGS}

clean:
	rm -f base16_decode
	rm -f base16_encode
	rm -f base64_decode
	rm -f base64_encode
	rm -f blake2b_buffer
	rm -f blake2s_buffer
	rm -f blake2s_file
	rm -f hmac_md5
	rm -f md5_buffer_alloc
	rm -f md5_buffer
	rm -f md5_file_alloc
	rm -f md5_file
	rm -f pbkdf2_alloc
	rm -f pbkdf2

