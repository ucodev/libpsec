#include <stdio.h>

#include <psec/hash.h>
#include <psec/kdf.h>

int main(void) {
	char pass[] = "test";
	char salt[] = "1234";
	char *digest = NULL, *fmt_digest = NULL;

	digest = kdf_pbkdf2_hash(NULL, hash_buffer_sha1, HASH_DIGEST_SIZE_SHA1, pass, sizeof(pass) - 1, salt, sizeof(salt) - 1, 10, HASH_DIGEST_SIZE_SHA1);
	fmt_digest = hash_format_hex(NULL, digest, HASH_DIGEST_SIZE_SHA1);

	puts(fmt_digest);

	hash_format_destroy(fmt_digest);
	kdf_destroy(digest);

	return 0;
}

