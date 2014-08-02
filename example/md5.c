#include <stdio.h>
#include <string.h>

#include <psec/hash.h>

int main(void) {
	char msg[] = "test";
	char digest[HASH_DIGEST_SIZE_MD5], fmt_digest[(HASH_DIGEST_SIZE_MD5 * 2) + 1];

	hash_md5_create(digest, msg, strlen(msg));
	hash_format_create_hex(fmt_digest, digest, HASH_DIGEST_SIZE_MD5);

	puts(fmt_digest);

	return 0;
}

