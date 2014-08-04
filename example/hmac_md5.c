#include <stdio.h>

#include <psec/encode.h>
#include <psec/hash.h>
#include <psec/mac.h>

int main(void) {
	char msg[] = "test";
	char pass[] = "test";
	char digest[HASH_DIGEST_SIZE_MD5], fmt_digest[HASH_FMT_DIGEST_SIZE_MD5];
	size_t out_len = 0;

	mac_hmac_hash(digest, hash_buffer_md5, HASH_DIGEST_SIZE_MD5, HASH_BLOCK_SIZE_MD5, pass, sizeof(pass) - 1, msg, sizeof(msg) - 1);
	encode_buffer_base16(fmt_digest, &out_len, digest, HASH_DIGEST_SIZE_MD5);

	puts(fmt_digest);

	return 0;
}

