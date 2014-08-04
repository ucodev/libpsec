#include <stdio.h>

#include <psec/encode.h>
#include <psec/hash.h>
#include <psec/kdf.h>

int main(void) {
	char pass[] = "test";
	char salt[] = "1234";
	char digest[HASH_DIGEST_SIZE_SHA1], fmt_digest[HASH_FMT_DIGEST_SIZE_SHA1];
	size_t out_len = 0;

	kdf_pbkdf2_hash(digest, hash_buffer_sha1, HASH_DIGEST_SIZE_SHA1, HASH_BLOCK_SIZE_SHA1, pass, sizeof(pass) - 1, salt, sizeof(salt) - 1, 10, HASH_DIGEST_SIZE_SHA1);
	encode_buffer_base16(fmt_digest, &out_len, digest, HASH_DIGEST_SIZE_SHA1);

	puts(fmt_digest);

	return 0;
}

