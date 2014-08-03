#include <stdio.h>

#include <psec/hash.h>
#include <psec/mac.h>

int main(void) {
	char msg[] = "test";
	char pass[] = "test";
	char digest[HASH_DIGEST_SIZE_MD5], fmt_digest[HASH_FMT_DIGEST_SIZE_MD5];

	mac_hmac_hash(digest, hash_buffer_md5, HASH_DIGEST_SIZE_MD5, HASH_BLOCK_SIZE_MD5, pass, sizeof(pass) - 1, msg, sizeof(msg) - 1);
	hash_format_hex(fmt_digest, digest, HASH_DIGEST_SIZE_MD5);

	puts(fmt_digest);

	return 0;
}

