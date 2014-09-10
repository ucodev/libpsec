#include <stdio.h>
#include <string.h>

#include <psec/crypt.h>

int main(void) {
	unsigned char plain[19] = "testing encryption";
	unsigned char encrypted[24];
	unsigned char decrypted[24];
	unsigned char key[CRYPT_KEY_SIZE_BLOWFISH448] = "weak";
	size_t encrypted_out_len = 0, decrypted_out_len = 0;

	crypt_encrypt_blowfish448ecb(encrypted, &encrypted_out_len, plain, sizeof(plain), NULL, key);

	crypt_decrypt_blowfish448ecb(decrypted, &decrypted_out_len, encrypted, encrypted_out_len, NULL, key);

	puts((char *) decrypted);

	return 0;
}

