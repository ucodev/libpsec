#include <stdio.h>
#include <errno.h>

void no_dh_support(void) {
	return;
}

unsigned char *dh_init_private_key(unsigned char *priv, size_t priv_size) {
	errno = ENOSYS;

	return NULL;
}

unsigned char *dh_compute_public_key(
	unsigned char *pub,
	size_t pub_size,
	const unsigned char *priv,
	size_t priv_size)
{
	errno = ENOSYS;

	return NULL;
}
	
unsigned char *dh_compute_shared_key(
	unsigned char *shared,
	const unsigned char *pub,
	size_t pub_size,
	const unsigned char *priv,
	size_t priv_size)
{
	errno = ENOSYS;

	return NULL;
}

