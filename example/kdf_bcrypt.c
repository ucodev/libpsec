#include <stdio.h>

#include <psec/encode.h>
#include <psec/kdf.h>

int main(void) {
	unsigned char pass[] = "test";
	unsigned char salt[16] = "1234123412341234";
	unsigned char digest[24], encoded_digest[(24 * 2) + 1];
	int cost = 10;
	size_t out_len = 0;

	kdf_bcrypt(digest, cost, pass, sizeof(pass) - 1, salt);
	encode_buffer_base16(encoded_digest, &out_len, digest, 24);

	puts((char *) encoded_digest);

	return 0;
}

