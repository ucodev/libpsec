#include <stdio.h>
#include <string.h>

#include <psec/ke.h>

int main(void) {
	unsigned char A_shared[256], A_pub[256], A_priv[64];
	unsigned char B_shared[256], B_pub[256], B_priv[64];

	ke_dh_private(A_priv, sizeof(A_priv));
	ke_dh_private(B_priv, sizeof(B_priv));

	ke_dh_public(A_pub, sizeof(A_pub), A_priv, sizeof(A_priv));
	ke_dh_public(B_pub, sizeof(B_pub), B_priv, sizeof(B_priv));

	ke_dh_shared(A_shared, B_pub, sizeof(B_pub), A_priv, sizeof(A_priv));
	ke_dh_shared(B_shared, A_pub, sizeof(A_pub), B_priv, sizeof(B_priv));

	if (!memcmp(A_shared, B_shared, sizeof(A_shared))) {
		puts("Keys match!");
		return 0;
	}

	puts("Keys don't match!");

	return -1;
}

