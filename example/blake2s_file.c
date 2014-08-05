#include <stdio.h>
#include <string.h>

#include <psec/encode.h>
#include <psec/hash.h>

int main(void) {
	FILE *fp = NULL;
	char digest[HASH_DIGEST_SIZE_BLAKE2S], fmt_digest[(HASH_DIGEST_SIZE_BLAKE2S * 2) + 1];
	size_t out_len = 0;

	fp = fopen("/etc/passwd", "r");

	hash_file_blake2s(digest, fp);
	encode_buffer_base16(fmt_digest, &out_len, digest, HASH_DIGEST_SIZE_BLAKE2S);

	puts(fmt_digest);

	fclose(fp);

	return 0;
}

