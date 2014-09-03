#include <stdio.h>
#include <string.h>

#include <psec/encode.h>
#include <psec/hash.h>

int main(void) {
	unsigned char msg[] = "test";
	unsigned char key[] = "test";
	unsigned char digest[HASH_DIGEST_SIZE_BLAKE2S], encoded_digest[(HASH_DIGEST_SIZE_BLAKE2S * 2) + 1];
	size_t out_len = 0;

	hash_buffer_blake2s_key(digest, msg, strlen((char *) msg), key, strlen((char *) key));
	encode_buffer_base16(encoded_digest, &out_len, digest, HASH_DIGEST_SIZE_BLAKE2S);

	puts((char *) encoded_digest);

	return 0;
}

