#include <stdio.h>
#include <string.h>

#include <psec/encode.h>
#include <psec/hash.h>

int main(void) {
	unsigned char msg[] = "test";
	unsigned char digest[HASH_DIGEST_SIZE_HAVAL192], encoded_digest[(HASH_DIGEST_SIZE_HAVAL192 * 2) + 1];
	size_t out_len = 0;

	hash_buffer_haval192(digest, msg, strlen((char *) msg));
	encode_buffer_base16(encoded_digest, &out_len, digest, HASH_DIGEST_SIZE_HAVAL192);

	puts((char *) encoded_digest);

	return 0;
}

