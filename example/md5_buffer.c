#include <stdio.h>
#include <string.h>

#include <psec/hash.h>

int main(void) {
	char msg[] = "test";
	char digest[HASH_DIGEST_SIZE_MD5], fmt_digest[HASH_FMT_DIGEST_SIZE_MD5];

	hash_buffer_md5(digest, msg, strlen(msg));
	hash_format_hex(fmt_digest, digest, HASH_DIGEST_SIZE_MD5);

	puts(fmt_digest);

	return 0;
}

