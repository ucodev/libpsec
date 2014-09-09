#include <stdio.h>

#include <psec/encode.h>
#include <psec/hash.h>
#include <psec/kdf.h>
#include <psec/mac.h>

int main(void) {
	unsigned char pass[] = "test";
	unsigned char salt[8] = "12341234";
	unsigned char digest[HASH_DIGEST_SIZE_MD2], encoded_digest[(HASH_DIGEST_SIZE_MD2 * 2) + 1];
	int rounds = 10;
	size_t out_len = 0;

	kdf_pbkdf1_md2(digest, pass, sizeof(pass) - 1, salt, rounds, HASH_DIGEST_SIZE_MD2);
	encode_buffer_base16(encoded_digest, &out_len, digest, HASH_DIGEST_SIZE_MD2);

	puts((char *) encoded_digest);

	return 0;
}

