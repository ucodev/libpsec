#include <stdio.h>
#include <string.h>

#include <psec/encode.h>
#include <psec/hash.h>

int main(void) {
	FILE *fp = NULL;
	char *digest = NULL, *fmt_digest = NULL;
	size_t out_len = 0;

	fp = fopen("/etc/passwd", "r");

	digest = hash_file_md5(NULL, fp);
	fmt_digest = encode_buffer_base16(NULL, &out_len, digest, HASH_DIGEST_SIZE_MD5);

	puts(fmt_digest);

	encode_destroy(fmt_digest);
	hash_destroy(digest);

	fclose(fp);

	return 0;
}

