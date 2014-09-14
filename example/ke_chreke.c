#include <stdio.h>
#include <string.h>

#include <psec/hash.h>
#include <psec/kdf.h>
#include <psec/ke.h>
#include <psec/mac.h>

int main(void) {
	const char salt[] = "xpto";
	const char password[] = "xpto123";
	unsigned char pwhash[HASH_DIGEST_SIZE_SHA512];

	unsigned char server_context[KE_CONTEXT_SIZE_CHREKE];
	unsigned char client_context[KE_CONTEXT_SIZE_CHREKE];

	unsigned char client_auth[KE_CLIENT_AUTH_SIZE_CHREKE];
	unsigned char client_session[KE_CLIENT_SESSION_SIZE_CHREKE];
	unsigned char server_session[KE_SERVER_SESSION_SIZE_CHREKE];

	unsigned char client_key_agreed[KE_KEY_SIZE_CHREKE];
	unsigned char server_key_agreed[KE_KEY_SIZE_CHREKE];

	/* Grant that keys are different before the test so we can grant that this is working
	 * properly.
	 */
	memset(client_key_agreed, 'C', sizeof(client_key_agreed));
	memset(server_key_agreed, 'S', sizeof(server_key_agreed));

	/* Create pwhash */
	kdf_pbkdf2_sha512(pwhash, (unsigned char *) password, strlen(password), (unsigned char *) salt, strlen(salt), 5000, HASH_DIGEST_SIZE_SHA512);

	/* Initialize client authentication */
	ke_chreke_client_init(client_session, client_context, password, (unsigned char *) salt, strlen(salt));

	/* Initialize server authentication */
	ke_chreke_server_init(server_session, server_context, client_session, pwhash);


	/* Authorize server */
	if (!ke_chreke_client_authorize(client_auth, client_context, client_key_agreed, server_session)) {
		puts("ke_chreke_client_authorize(): failed.");
		return 1;
	}

	/* Authorize client */
	if (ke_chreke_server_authorize(server_context, server_key_agreed, client_auth, (unsigned char *) salt, strlen(salt)) < 0) {
		puts("ke_chreke_server_authorize(): failed.");
		return 1;
	}

	/* Compare agreed keys */
	if (!memcmp(client_key_agreed, server_key_agreed, sizeof(server_key_agreed))) {
		puts("Keys match!");
		return 0;
	}

	puts("Keys don't match!");

	return 1;
}

