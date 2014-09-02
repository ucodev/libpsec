#include <stdio.h>
#include <string.h>

#include <psec/encode.h>
#include <psec/hash.h>

int main(void) {
	unsigned char msg[] = "test";
	unsigned char *digest = NULL, *encoded_digest = NULL;
	size_t out_len = 0;

	digest = hash_buffer_md5(NULL, msg, strlen((char *) msg));
	encoded_digest = encode_buffer_base16(NULL, &out_len, digest, HASH_DIGEST_SIZE_MD5);

	puts((char *) encoded_digest);

	encode_destroy(encoded_digest);
	hash_destroy(digest);

	return 0;
}

