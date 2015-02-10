#include <errno.h>

void no_auth_shadow_support(void) {
	return;
}

int shadow_user_pass_verify(const char *username, const char *password) {
	errno = ENOSYS;

	return -1;
}

