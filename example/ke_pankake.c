#include <stdio.h>
#include <string.h>

#include <psec/hash.h>
#include <psec/kdf.h>
#include <psec/ke.h>

int main(void) {
	const char salt[] = "xpto";
	const char password[] = "xpto123";
	unsigned char pwhash[HASH_DIGEST_SIZE_SHA512];

	unsigned char client_auth[KE_CLIENT_AUTH_SIZE_PANKAKE];
	unsigned char client_session[KE_CLIENT_SESSION_SIZE_PANKAKE];
	unsigned char server_session[KE_SERVER_SESSION_SIZE_PANKAKE];

	unsigned char client_shared[512], client_pub[512], client_priv[256];
	unsigned char server_shared[512], server_pub[512], server_priv[256];

	unsigned char client_key_agreed[32];
	unsigned char server_key_agreed[32];

	/* Grant that keys are different before the test so we can grant that this is working
	 * properly.
	 */
	memset(client_key_agreed, 'C', sizeof(client_key_agreed));
	memset(server_key_agreed, 'S', sizeof(server_key_agreed));

	/* Create pwhash */
	kdf_pbkdf2_hash(pwhash, hash_buffer_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, (unsigned char *) password, strlen(password), (unsigned char *) salt, strlen(salt), 5000, HASH_DIGEST_SIZE_SHA512);

	/* Create private keys */
	ke_dh_private(client_priv, sizeof(client_priv));
	ke_dh_private(server_priv, sizeof(server_priv));

	/* Create public keys */
	ke_dh_public(client_pub, sizeof(client_pub), client_priv, sizeof(client_priv));
	ke_dh_public(server_pub, sizeof(server_pub), server_priv, sizeof(server_priv));

	/* Initialize client authentication */
	ke_pankake_client_init(client_session, client_pub, sizeof(client_pub), password, (unsigned char *) salt, strlen(salt));

	/* Initialize server authentication */
	ke_pankake_server_init(server_session, server_key_agreed, server_shared, server_pub, sizeof(server_pub), server_priv, sizeof(server_priv), client_session, pwhash);


	/* Authorize server */
	if (!ke_pankake_client_authorize(client_auth, client_key_agreed, client_shared, client_pub, sizeof(client_pub), client_priv, sizeof(client_priv), server_session, client_session, password, (unsigned char *) salt, strlen(salt))) {
		puts("ke_pankake_client_authorize(): failed.");
		return 1;
	}

	/* Authorize client */
	if (ke_pankake_server_authorize(server_key_agreed, client_auth, pwhash, (unsigned char *) salt, strlen(salt)) < 0) {
		puts("ke_pankake_server_authorize(): failed.");
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

