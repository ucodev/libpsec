CC=`cat ../.compiler`
LDFLAGS=-lpsec -lcrypt `cat ../.libs`

all:
	/bin/bash -c 'if [ -e ../.lgmp ]; then ${CC} -o ke_dh ke_dh.c ${LDFLAGS}; fi'
	${CC} -o auth_shadow auth_shadow.c ${LDFLAGS}
	${CC} -o base16_decode base16_decode.c ${LDFLAGS}
	${CC} -o base16_decode_small_buf base16_decode_small_buf.c ${LDFLAGS}
	${CC} -o base16_encode base16_encode.c ${LDFLAGS}
	${CC} -o base16_encode_small_buf base16_encode_small_buf.c ${LDFLAGS}
	${CC} -o base64_decode base64_decode.c ${LDFLAGS}
	${CC} -o base64_decode_small_buf base64_decode_small_buf.c ${LDFLAGS}
	${CC} -o base64_encode base64_encode.c ${LDFLAGS}
	${CC} -o base64_encode_small_buf base64_encode_small_buf.c ${LDFLAGS}
	${CC} -o blake2b_buffer blake2b_buffer.c ${LDFLAGS}
	${CC} -o blake2s_buffer blake2s_buffer.c ${LDFLAGS}
	${CC} -o blake2s_file blake2s_file.c ${LDFLAGS}
	${CC} -o crypt_chacha20 crypt_chacha20.c ${LDFLAGS}
	${CC} -o crypt_chacha20poly1305 crypt_chacha20poly1305.c ${LDFLAGS}
	${CC} -o crypt_otp crypt_otp.c ${LDFLAGS}
	${CC} -o crypt_xsalsa20 crypt_xsalsa20.c ${LDFLAGS}
	${CC} -o crypt_xsalsa20poly1305 crypt_xsalsa20poly1305.c ${LDFLAGS}
	${CC} -o hmac_md5 hmac_md5.c ${LDFLAGS}
	${CC} -o ke_dheke ke_dheke.c ${LDFLAGS}
	${CC} -o ke_ecdh ke_ecdh.c ${LDFLAGS}
	${CC} -o ke_pankake ke_pankake.c ${LDFLAGS}
	${CC} -o md5_buffer_alloc md5_buffer_alloc.c ${LDFLAGS}
	${CC} -o md5_buffer md5_buffer.c ${LDFLAGS}
	${CC} -o md5_file_alloc md5_file_alloc.c ${LDFLAGS}
	${CC} -o md5_file md5_file.c ${LDFLAGS}
	${CC} -o pbkdf2_alloc pbkdf2_alloc.c ${LDFLAGS}
	${CC} -o pbkdf2 pbkdf2.c ${LDFLAGS}
	${CC} -o random random.c ${LDFLAGS}
	${CC} -o random_dict random_dict.c ${LDFLAGS}

clean:
	rm -f auth_shadow
	rm -f base16_decode
	rm -f base16_decode_small_buf
	rm -f base16_encode
	rm -f base16_encode_small_buf
	rm -f base64_decode
	rm -f base64_decode_small_buf
	rm -f base64_encode
	rm -f base64_encode_small_buf
	rm -f blake2b_buffer
	rm -f blake2s_buffer
	rm -f blake2s_file
	rm -f crypt_chacha20
	rm -f crypt_chacha20poly1305
	rm -f crypt_otp
	rm -f crypt_xsalsa20
	rm -f crypt_xsalsa20poly1305
	rm -f hmac_md5
	rm -f ke_dh 
	rm -f ke_dheke
	rm -f ke_ecdh 
	rm -f ke_pankake
	rm -f md5_buffer_alloc
	rm -f md5_buffer
	rm -f md5_file_alloc
	rm -f md5_file
	rm -f pbkdf2_alloc
	rm -f pbkdf2
	rm -f random
	rm -f random_dict

