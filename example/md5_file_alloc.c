#include <stdio.h>
#include <string.h>

#include <psec/hash.h>

int main(void) {
	FILE *fp = NULL;
	char *digest = NULL, *fmt_digest = NULL;

	fp = fopen("/etc/passwd", "r");

	digest = hash_file_md5(NULL, fp);
	fmt_digest = hash_format_hex(NULL, digest, HASH_DIGEST_SIZE_MD5);

	puts(fmt_digest);

	hash_format_destroy(fmt_digest);
	hash_destroy(digest);

	fclose(fp);

	return 0;
}

