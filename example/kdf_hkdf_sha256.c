#include <stdio.h>

#include <psec/encode.h>
#include <psec/hash.h>
#include <psec/kdf.h>

int main(void) {
	unsigned char ikm[22] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
	unsigned char digest[42], encoded_digest[(42 * 2) + 1];
	size_t out_len = 0;

	kdf_hkdf_sha256(digest, ikm, sizeof(ikm), (unsigned char *) "", 0, (unsigned char *) "", 0, 42);
	encode_buffer_base16(encoded_digest, &out_len, digest, 42);

	puts((char *) encoded_digest);

	return 0;
}

