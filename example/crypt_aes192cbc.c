#include <stdio.h>
#include <string.h>

#include <psec/crypt.h>

int main(void) {
	unsigned char plain[19] = "testing encryption";
	unsigned char *encrypted = NULL;
	unsigned char *decrypted = NULL;
	unsigned char key[CRYPT_KEY_SIZE_AES192] = "weak";
	unsigned char nonce[CRYPT_NONCE_SIZE_AES192] = "random";
	size_t encrypted_out_len = 0, decrypted_out_len = 0;

	encrypted = crypt_encrypt_aes192cbc(NULL, &encrypted_out_len, plain, sizeof(plain), nonce, key);

	decrypted = crypt_decrypt_aes192cbc(NULL, &decrypted_out_len, encrypted, encrypted_out_len, nonce, key);

	puts((char *) decrypted);

	crypt_destroy(encrypted);
	crypt_destroy(decrypted);

	return 0;
}

