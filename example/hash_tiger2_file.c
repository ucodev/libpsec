#include <stdio.h>
#include <string.h>

#include <psec/encode.h>
#include <psec/hash.h>

int main(void) {
	FILE *fp = NULL;
	unsigned char digest[HASH_DIGEST_SIZE_TIGER2], encoded_digest[(HASH_DIGEST_SIZE_TIGER2 * 2) + 1];
	size_t out_len = 0;

	fp = fopen("/etc/passwd", "r");

	hash_file_tiger2(digest, fp);
	encode_buffer_base16(encoded_digest, &out_len, digest, HASH_DIGEST_SIZE_TIGER2);

	puts((char *) encoded_digest);

	fclose(fp);

	return 0;
}

