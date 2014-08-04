#include <stdio.h>
#include <string.h>

#include <psec/encode.h>
#include <psec/hash.h>

int main(void) {
	FILE *fp = NULL;
	char digest[HASH_DIGEST_SIZE_MD5], fmt_digest[HASH_FMT_DIGEST_SIZE_MD5];
	size_t out_len = 0;

	fp = fopen("/etc/passwd", "r");

	hash_file_md5(digest, fp);
	encode_buffer_base16(fmt_digest, &out_len, digest, HASH_DIGEST_SIZE_MD5);

	puts(fmt_digest);

	fclose(fp);

	return 0;
}

