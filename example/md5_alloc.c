#include <stdio.h>
#include <string.h>

#include <psec/hash.h>

int main(void) {
	char msg[] = "test";
	char *digest = NULL, *fmt_digest = NULL;

	digest = hash_md5_create(NULL, msg, strlen(msg));
	fmt_digest = hash_format_create_hex(NULL, digest, HASH_DIGEST_SIZE_MD5);

	puts(fmt_digest);

	hash_md5_destroy(digest);
	hash_format_destroy(fmt_digest);

	return 0;
}

