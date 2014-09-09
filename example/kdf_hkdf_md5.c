#include <stdio.h>

#include <psec/encode.h>
#include <psec/kdf.h>

int main(void) {
	unsigned char ikm[] = "test";
	unsigned char salt[] = "1234";
	unsigned char info[] = "appinfo";
	unsigned char digest[HASH_DIGEST_SIZE_MD5], encoded_digest[(HASH_DIGEST_SIZE_MD5 * 2) + 1];
	size_t out_len = 0;

	kdf_hkdf_md5(digest, ikm, sizeof(ikm) - 1, salt, sizeof(salt) - 1, info, sizeof(info) - 1, HASH_DIGEST_SIZE_MD5);
	encode_buffer_base16(encoded_digest, &out_len, digest, HASH_DIGEST_SIZE_MD5);

	puts((char *) encoded_digest);

	return 0;
}

