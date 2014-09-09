#include <stdio.h>

#include <psec/encode.h>
#include <psec/hash.h>
#include <psec/kdf.h>

int main(void) {
	unsigned char pass[] = "test";
	unsigned char salt[] = "1234";
	unsigned char digest[HASH_DIGEST_SIZE_SHA512], encoded_digest[(HASH_DIGEST_SIZE_SHA512 * 2) + 1];
	int rounds = 10;
	size_t out_len = 0;

	kdf_pbkdf2_sha512(digest, pass, sizeof(pass) - 1, salt, sizeof(salt) - 1, rounds, HASH_DIGEST_SIZE_SHA512);
	encode_buffer_base16(encoded_digest, &out_len, digest, HASH_DIGEST_SIZE_SHA512);

	puts((char *) encoded_digest);

	return 0;
}

