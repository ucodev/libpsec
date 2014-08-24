#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <psec/ke.h>

int main(void) {
	const char salt[] = "xpto";
	const char password[] = "xpto123";

	unsigned char server_context[KE_CONTEXT_SIZE_DHEKE];
	unsigned char client_context[KE_CONTEXT_SIZE_DHEKE];

	unsigned char client_key_agreed[512];
	unsigned char server_key_agreed[512];

	unsigned char client_session[512 + KE_EXTRA_SESSION_SIZE_DHEKE];
	unsigned char server_session[512 + KE_EXTRA_SESSION_SIZE_DHEKE];

	/* Grant that keys are different before the test so we can grant that this is working
	 * properly.
	 */
	memset(client_key_agreed, 'C', sizeof(client_key_agreed));
	memset(server_key_agreed, 'S', sizeof(server_key_agreed));

	/* Initialize client session for authentication */
	if (!ke_dheke_client_init(client_session, client_context, (unsigned char *) password, strlen(password), (unsigned char *) salt, strlen(salt), 256, 512, 1000, 1)) {
		printf("ke_dheke_client_init(): %s\n", strerror(errno));
		return 1;
	}

	/* Initialize server session for authentication */
	if (!ke_dheke_server_init(server_session, server_key_agreed, server_context, client_session, (unsigned char *) password, strlen(password), (unsigned char *) salt, strlen(salt), 256, 512, 1000, 1)) {
		printf("ke_dheke_server_init(): %s\n", strerror(errno));
		return 1;
	}

	/* Process session response from server */
	if (!ke_dheke_client_process(client_key_agreed, client_context, server_session)) {
		printf("ke_dheke_client_process(): %s\n", strerror(errno));
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

