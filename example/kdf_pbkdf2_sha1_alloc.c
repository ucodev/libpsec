#include <stdio.h>

#include <psec/encode.h>
#include <psec/hash.h>
#include <psec/kdf.h>

int main(void) {
	unsigned char pass[] = "test";
	unsigned char salt[] = "1234";
	unsigned char *digest = NULL, *encoded_digest = NULL;
	size_t out_len = 0;

	digest = kdf_pbkdf2_hash(NULL, hash_buffer_sha1, HASH_DIGEST_SIZE_SHA1, HASH_BLOCK_SIZE_SHA1, pass, sizeof(pass) - 1, salt, sizeof(salt) - 1, 10, HASH_DIGEST_SIZE_SHA1);
	encoded_digest = encode_buffer_base16(NULL, &out_len, digest, HASH_DIGEST_SIZE_SHA1);

	puts((char *) encoded_digest);

	encode_destroy(encoded_digest);
	kdf_destroy(digest);

	return 0;
}

