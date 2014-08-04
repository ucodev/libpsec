#include <stdio.h>
#include <string.h>

#include <psec/encode.h>
#include <psec/hash.h>

int main(void) {
	char msg[] = "test";
	char *digest = NULL, *fmt_digest = NULL;
	size_t out_len = 0;

	digest = hash_buffer_md5(NULL, msg, strlen(msg));
	fmt_digest = encode_buffer_base16(NULL, &out_len, digest, HASH_DIGEST_SIZE_MD5);

	puts(fmt_digest);

	encode_destroy(fmt_digest);
	hash_destroy(digest);

	return 0;
}

