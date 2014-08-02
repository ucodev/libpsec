#include <stdio.h>
#include <string.h>

#include <psec/hash.h>

int main(void) {
	FILE *fp = NULL;
	char digest[HASH_DIGEST_SIZE_MD5], fmt_digest[(HASH_DIGEST_SIZE_MD5 * 2) + 1];

	fp = fopen("/etc/passwd", "r");

	hash_file_md5(digest, fp);
	hash_format_hex(fmt_digest, digest, HASH_DIGEST_SIZE_MD5);

	puts(fmt_digest);

	fclose(fp);

	return 0;
}

