#include <stdio.h>
#include <string.h>

#include <psec/crypt.h>
#include <psec/generate.h>

int main(void) {
	unsigned char plain[19] = "testing encryption";
	unsigned char encrypted[19];
	unsigned char decrypted[19];
	unsigned char key[19];
	unsigned char nonce[19];
	size_t encrypted_out_len = 0, decrypted_out_len = 0;

	/* Generate a random key and nonce */
	generate_bytes_random(key, sizeof(key));
	generate_bytes_random(nonce, sizeof(nonce));

	/* Testing with nonce */
	crypt_encrypt_otp(encrypted, &encrypted_out_len, plain, sizeof(plain), nonce, key);

	crypt_decrypt_otp(decrypted, &decrypted_out_len, encrypted, encrypted_out_len, nonce, key);

	puts((char *) decrypted);

	/* Testing without nonce */
	crypt_encrypt_otp(encrypted, &encrypted_out_len, plain, sizeof(plain), NULL, key);

	crypt_decrypt_otp(decrypted, &decrypted_out_len, encrypted, encrypted_out_len, NULL, key);

	puts((char *) decrypted);

	return 0;
}

