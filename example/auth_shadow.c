#include <stdio.h>
#include <unistd.h>

#include <psec/auth.h>


int main(int argc, char *argv[]) {
	char *username = NULL, *password = NULL;

	if (argc != 3) {
		printf("Usage: %s <username> <password>\n", argv[0]);
		return 1;
	}

	if (getuid()) {
		puts("You need to be root.");
		return 1;
	}

	username = argv[1];
	password = argv[2];

	if (auth_shadow_verify(username, password) < 0) {
		puts("Authentication failed.");
		return 1;
	}

	puts("Authentication successful.");

	return 0;
}

