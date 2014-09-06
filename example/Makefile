CC=`cat ../.compiler`
LDFLAGS=-lpsec `cat ../.libs`

all:
	/bin/sh -c 'if [ -e ../.lgmp ]; then ${CC} -o ke_dh ke_dh.c ${LDFLAGS}; fi'
	/bin/sh -c 'if [ -e ../.lcrypt ]; then ${CC} -o auth_shadow auth_shadow.c ${LDFLAGS}; fi'
	${CC} -o encode_base16 encode_base16.c ${LDFLAGS}
	${CC} -o encode_base16_small_buf encode_base16_small_buf.c ${LDFLAGS}
	${CC} -o encode_base64 encode_base64.c ${LDFLAGS}
	${CC} -o encode_base64_small_buf encode_base64_small_buf.c ${LDFLAGS}
	${CC} -o decode_base16 decode_base16.c ${LDFLAGS}
	${CC} -o decode_base16_small_buf decode_base16_small_buf.c ${LDFLAGS}
	${CC} -o decode_base64 decode_base64.c ${LDFLAGS}
	${CC} -o decode_base64_small_buf decode_base64_small_buf.c ${LDFLAGS}
	${CC} -o crypt_aes128cbc crypt_aes128cbc.c ${LDFLAGS}
	${CC} -o crypt_aes128ecb crypt_aes128ecb.c ${LDFLAGS}
	${CC} -o crypt_aes192cbc crypt_aes192cbc.c ${LDFLAGS}
	${CC} -o crypt_aes192ecb crypt_aes192ecb.c ${LDFLAGS}
	${CC} -o crypt_aes256cbc crypt_aes256cbc.c ${LDFLAGS}
	${CC} -o crypt_aes256ecb crypt_aes256ecb.c ${LDFLAGS}
	${CC} -o crypt_chacha20 crypt_chacha20.c ${LDFLAGS}
	${CC} -o crypt_chacha20poly1305 crypt_chacha20poly1305.c ${LDFLAGS}
	${CC} -o crypt_otp crypt_otp.c ${LDFLAGS}
	${CC} -o crypt_xsalsa20 crypt_xsalsa20.c ${LDFLAGS}
	${CC} -o crypt_xsalsa20poly1305 crypt_xsalsa20poly1305.c ${LDFLAGS}
	${CC} -o generate_random generate_random.c ${LDFLAGS}
	${CC} -o generate_random_dict generate_random_dict.c ${LDFLAGS}
	${CC} -o hash_blake224_buffer hash_blake224_buffer.c ${LDFLAGS}
	${CC} -o hash_blake256_buffer hash_blake256_buffer.c ${LDFLAGS}
	${CC} -o hash_blake384_buffer hash_blake384_buffer.c ${LDFLAGS}
	${CC} -o hash_blake512_buffer hash_blake512_buffer.c ${LDFLAGS}
	${CC} -o hash_blake2b_buffer hash_blake2b_buffer.c ${LDFLAGS}
	${CC} -o hash_blake2s_buffer hash_blake2s_buffer.c ${LDFLAGS}
	${CC} -o hash_blake2s_buffer_key hash_blake2s_buffer_key.c ${LDFLAGS}
	${CC} -o hash_blake2s_file hash_blake2s_file.c ${LDFLAGS}
	${CC} -o hash_gost_buffer hash_gost_buffer.c ${LDFLAGS}
	${CC} -o hash_gost_file hash_gost_file.c ${LDFLAGS}
	${CC} -o hash_haval256_buffer hash_haval256_buffer.c ${LDFLAGS}
	${CC} -o hash_haval224_buffer hash_haval224_buffer.c ${LDFLAGS}
	${CC} -o hash_haval192_buffer hash_haval192_buffer.c ${LDFLAGS}
	${CC} -o hash_haval160_buffer hash_haval160_buffer.c ${LDFLAGS}
	${CC} -o hash_haval128_buffer hash_haval128_buffer.c ${LDFLAGS}
	${CC} -o hash_haval256_file hash_haval256_file.c ${LDFLAGS}
	${CC} -o hash_md2_buffer hash_md2_buffer.c ${LDFLAGS}
	${CC} -o hash_md4_buffer hash_md4_buffer.c ${LDFLAGS}
	${CC} -o hash_md5_buffer hash_md5_buffer.c ${LDFLAGS}
	${CC} -o hash_md5_buffer_alloc hash_md5_buffer_alloc.c ${LDFLAGS}
	${CC} -o hash_md5_file hash_md5_file.c ${LDFLAGS}
	${CC} -o hash_md5_file_alloc hash_md5_file_alloc.c ${LDFLAGS}
	${CC} -o hash_ripemd128_buffer hash_ripemd128_buffer.c ${LDFLAGS}
	${CC} -o hash_ripemd128_file hash_ripemd128_file.c ${LDFLAGS}
	${CC} -o hash_ripemd160_buffer hash_ripemd160_buffer.c ${LDFLAGS}
	${CC} -o hash_ripemd160_file hash_ripemd160_file.c ${LDFLAGS}
	${CC} -o hash_sha1_buffer hash_sha1_buffer.c ${LDFLAGS}
	${CC} -o hash_sha224_buffer hash_sha224_buffer.c ${LDFLAGS}
	${CC} -o hash_sha256_buffer hash_sha256_buffer.c ${LDFLAGS}
	${CC} -o hash_sha384_buffer hash_sha384_buffer.c ${LDFLAGS}
	${CC} -o hash_sha512_buffer hash_sha512_buffer.c ${LDFLAGS}
	${CC} -o hash_whirlpool_buffer hash_whirlpool_buffer.c ${LDFLAGS}
	${CC} -o hash_whirlpool_file hash_whirlpool_file.c ${LDFLAGS}
	${CC} -o hmac_generic hmac_generic.c ${LDFLAGS}
	${CC} -o hmac_blake224 hmac_blake224.c ${LDFLAGS}
	${CC} -o hmac_blake256 hmac_blake256.c ${LDFLAGS}
	${CC} -o hmac_blake384 hmac_blake384.c ${LDFLAGS}
	${CC} -o hmac_blake512 hmac_blake512.c ${LDFLAGS}
	${CC} -o hmac_blake2b hmac_blake2b.c ${LDFLAGS}
	${CC} -o hmac_blake2s hmac_blake2s.c ${LDFLAGS}
	${CC} -o hmac_gost hmac_gost.c ${LDFLAGS}
	${CC} -o hmac_haval256 hmac_haval256.c ${LDFLAGS}
	${CC} -o hmac_haval224 hmac_haval224.c ${LDFLAGS}
	${CC} -o hmac_haval192 hmac_haval192.c ${LDFLAGS}
	${CC} -o hmac_haval160 hmac_haval160.c ${LDFLAGS}
	${CC} -o hmac_haval128 hmac_haval128.c ${LDFLAGS}
	${CC} -o hmac_md2 hmac_md2.c ${LDFLAGS}
	${CC} -o hmac_md4 hmac_md4.c ${LDFLAGS}
	${CC} -o hmac_md5 hmac_md5.c ${LDFLAGS}
	${CC} -o hmac_ripemd128 hmac_ripemd128.c ${LDFLAGS}
	${CC} -o hmac_ripemd160 hmac_ripemd160.c ${LDFLAGS}
	${CC} -o hmac_sha1 hmac_sha1.c ${LDFLAGS}
	${CC} -o hmac_sha224 hmac_sha224.c ${LDFLAGS}
	${CC} -o hmac_sha256 hmac_sha256.c ${LDFLAGS}
	${CC} -o hmac_sha384 hmac_sha384.c ${LDFLAGS}
	${CC} -o hmac_sha512 hmac_sha512.c ${LDFLAGS}
	${CC} -o hmac_whirlpool hmac_whirlpool.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_generic kdf_pbkdf2_generic.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_generic_alloc kdf_pbkdf2_generic_alloc.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_blake224 kdf_pbkdf2_blake224.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_blake256 kdf_pbkdf2_blake256.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_blake384 kdf_pbkdf2_blake384.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_blake512 kdf_pbkdf2_blake512.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_blake2b kdf_pbkdf2_blake2b.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_blake2s kdf_pbkdf2_blake2s.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_gost kdf_pbkdf2_gost.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_haval256 kdf_pbkdf2_haval256.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_haval224 kdf_pbkdf2_haval224.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_haval192 kdf_pbkdf2_haval192.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_haval160 kdf_pbkdf2_haval160.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_haval128 kdf_pbkdf2_haval128.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_md2 kdf_pbkdf2_md2.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_md4 kdf_pbkdf2_md4.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_md5 kdf_pbkdf2_md5.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_ripemd128 kdf_pbkdf2_ripemd128.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_ripemd160 kdf_pbkdf2_ripemd160.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_sha1 kdf_pbkdf2_sha1.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_sha224 kdf_pbkdf2_sha224.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_sha256 kdf_pbkdf2_sha256.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_sha384 kdf_pbkdf2_sha384.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_sha512 kdf_pbkdf2_sha512.c ${LDFLAGS}
	${CC} -o kdf_pbkdf2_whirlpool kdf_pbkdf2_whirlpool.c ${LDFLAGS}
	${CC} -o ke_dheke ke_dheke.c ${LDFLAGS}
	${CC} -o ke_ecdh ke_ecdh.c ${LDFLAGS}
	${CC} -o ke_pankake ke_pankake.c ${LDFLAGS}
	${CC} -o tc_memcmp tc_memcmp.c ${LDFLAGS}
	${CC} -o tc_memcpy tc_memcpy.c ${LDFLAGS}
	${CC} -o tc_memmove tc_memmove.c ${LDFLAGS}
	${CC} -o tc_memset tc_memset.c ${LDFLAGS}

clean:
	rm -f auth_shadow
	rm -f encode_base16
	rm -f encode_base16_small_buf
	rm -f encode_base64
	rm -f encode_base64_small_buf
	rm -f decode_base16
	rm -f decode_base16_small_buf
	rm -f decode_base64
	rm -f decode_base64_small_buf
	rm -f crypt_aes128cbc
	rm -f crypt_aes128ecb
	rm -f crypt_aes192cbc
	rm -f crypt_aes192ecb
	rm -f crypt_aes256cbc
	rm -f crypt_aes256ecb
	rm -f crypt_chacha20
	rm -f crypt_chacha20poly1305
	rm -f crypt_otp
	rm -f crypt_xsalsa20
	rm -f crypt_xsalsa20poly1305
	rm -f generate_random
	rm -f generate_random_dict
	rm -f hash_blake224_buffer
	rm -f hash_blake256_buffer
	rm -f hash_blake384_buffer
	rm -f hash_blake512_buffer
	rm -f hash_blake2b_buffer
	rm -f hash_blake2s_buffer
	rm -f hash_blake2s_buffer_key
	rm -f hash_blake2s_file
	rm -f hash_gost_buffer
	rm -f hash_gost_file
	rm -f hash_haval256_buffer
	rm -f hash_haval224_buffer
	rm -f hash_haval192_buffer
	rm -f hash_haval160_buffer
	rm -f hash_haval128_buffer
	rm -f hash_haval256_file
	rm -f hash_md2_buffer
	rm -f hash_md4_buffer
	rm -f hash_md5_buffer
	rm -f hash_md5_buffer_alloc
	rm -f hash_md5_file
	rm -f hash_md5_file_alloc
	rm -f hash_ripemd128_buffer
	rm -f hash_ripemd128_file
	rm -f hash_ripemd160_buffer
	rm -f hash_ripemd160_file
	rm -f hash_sha1_buffer
	rm -f hash_sha224_buffer
	rm -f hash_sha256_buffer
	rm -f hash_sha384_buffer
	rm -f hash_sha512_buffer
	rm -f hash_whirlpool_buffer
	rm -f hash_whirlpool_file
	rm -f hmac_generic
	rm -f hmac_blake224
	rm -f hmac_blake256
	rm -f hmac_blake384
	rm -f hmac_blake512
	rm -f hmac_blake2b
	rm -f hmac_blake2s
	rm -f hmac_gost
	rm -f hmac_haval256
	rm -f hmac_haval224
	rm -f hmac_haval192
	rm -f hmac_haval160
	rm -f hmac_haval128
	rm -f hmac_md2
	rm -f hmac_md4
	rm -f hmac_md5
	rm -f hmac_ripemd128
	rm -f hmac_ripemd160
	rm -f hmac_sha1
	rm -f hmac_sha224
	rm -f hmac_sha256
	rm -f hmac_sha384
	rm -f hmac_sha512
	rm -f hmac_whirlpool
	rm -f kdf_pbkdf2_generic_alloc
	rm -f kdf_pbkdf2_generic
	rm -f kdf_pbkdf2_blake224
	rm -f kdf_pbkdf2_blake256
	rm -f kdf_pbkdf2_blake384
	rm -f kdf_pbkdf2_blake512
	rm -f kdf_pbkdf2_blake2b
	rm -f kdf_pbkdf2_blake2s
	rm -f kdf_pbkdf2_gost
	rm -f kdf_pbkdf2_haval256
	rm -f kdf_pbkdf2_haval224
	rm -f kdf_pbkdf2_haval192
	rm -f kdf_pbkdf2_haval160
	rm -f kdf_pbkdf2_haval128
	rm -f kdf_pbkdf2_md2
	rm -f kdf_pbkdf2_md4
	rm -f kdf_pbkdf2_md5
	rm -f kdf_pbkdf2_ripemd128
	rm -f kdf_pbkdf2_ripemd160
	rm -f kdf_pbkdf2_sha1
	rm -f kdf_pbkdf2_sha224
	rm -f kdf_pbkdf2_sha256
	rm -f kdf_pbkdf2_sha384
	rm -f kdf_pbkdf2_sha512
	rm -f kdf_pbkdf2_whirlpool
	rm -f ke_dh 
	rm -f ke_dheke
	rm -f ke_ecdh 
	rm -f ke_pankake
	rm -f tc_memcmp
	rm -f tc_memcpy
	rm -f tc_memmove
	rm -f tc_memset

