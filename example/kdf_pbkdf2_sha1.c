#include <stdio.h>

#include <psec/encode.h>
#include <psec/hash.h>
#include <psec/kdf.h>
#include <psec/mac.h>

int main(void) {
	unsigned char pass[] = "test";
	unsigned char salt[] = "1234";
	unsigned char digest[HASH_DIGEST_SIZE_SHA1], encoded_digest[(HASH_DIGEST_SIZE_SHA1 * 2) + 1];
	size_t out_len = 0;

	kdf_pbkdf2_hash(digest, mac_hmac_sha1, HASH_DIGEST_SIZE_SHA1, HASH_BLOCK_SIZE_SHA1, pass, sizeof(pass) - 1, salt, sizeof(salt) - 1, 10, HASH_DIGEST_SIZE_SHA1);
	encode_buffer_base16(encoded_digest, &out_len, digest, HASH_DIGEST_SIZE_SHA1);

	puts((char *) encoded_digest);

	return 0;
}

