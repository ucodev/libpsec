#include <stdio.h>

#include <psec/encode.h>
#include <psec/hash.h>
#include <psec/mac.h>

int main(void) {
	unsigned char msg[] = "test";
	unsigned char pass[] = "test";
	unsigned char digest[HASH_DIGEST_SIZE_GOST], encoded_digest[(HASH_DIGEST_SIZE_GOST * 2) + 1];
	size_t out_len = 0;

	mac_hmac_gost(digest, pass, sizeof(pass) - 1, msg, sizeof(msg) - 1);
	encode_buffer_base16(encoded_digest, &out_len, digest, HASH_DIGEST_SIZE_GOST);

	puts((char *) encoded_digest);

	return 0;
}

