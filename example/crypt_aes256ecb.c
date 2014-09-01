#include <stdio.h>
#include <string.h>

#include <psec/crypt.h>

int main(void) {
	unsigned char plain[19] = "testing encryption";
	unsigned char *encrypted = NULL;
	unsigned char *decrypted = NULL;
	unsigned char key[CRYPT_KEY_SIZE_AES256] = "weak";
	size_t encrypted_out_len = 0, decrypted_out_len = 0;

	encrypted = crypt_encrypt_aes256ecb(NULL, &encrypted_out_len, plain, sizeof(plain), NULL, key);

	decrypted = crypt_decrypt_aes256ecb(NULL, &decrypted_out_len, encrypted, encrypted_out_len, NULL, key);

	puts((char *) decrypted);

	crypt_destroy(encrypted);
	crypt_destroy(decrypted);

	return 0;
}

