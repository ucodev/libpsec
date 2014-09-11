#include <stdio.h>

#include <psec/encode.h>
#include <psec/kdf.h>

int main(void) {
	unsigned char pass[] = "test";
	unsigned char salt[16] = "1234123412341234";
	unsigned char digest[32], encoded_digest[(32 * 2) + 1];
	size_t out_len = 0;

	if (!kdf_scrypt(digest, pass, sizeof(pass) - 1, salt, sizeof(salt) - 1, 1024, 8, 16, 32))
		return 1;

	encode_buffer_base16(encoded_digest, &out_len, digest, 32);

	puts((char *) encoded_digest);

	return 0;
}

