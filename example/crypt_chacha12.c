#include <stdio.h>
#include <string.h>

#include <psec/crypt.h>

int main(void) {
	unsigned char plain[19] = "testing encryption";
	unsigned char encrypted[19];
	unsigned char decrypted[19];
	unsigned char key[CRYPT_KEY_SIZE_CHACHA12] = "weak";
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA12] = "random";
	size_t encrypted_out_len = 0, decrypted_out_len = 0;

	crypt_encrypt_chacha12(encrypted, &encrypted_out_len, plain, sizeof(plain), nonce, key);

	crypt_decrypt_chacha12(decrypted, &decrypted_out_len, encrypted, encrypted_out_len, nonce, key);

	puts((char *) decrypted);

	return 0;
}

