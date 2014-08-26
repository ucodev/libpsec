#include <stdio.h>
#include <string.h>

#include <psec/ke.h>

int main(void) {
	unsigned char A_shared[32], A_pub[32], A_priv[32];
	unsigned char B_shared[32], B_pub[32], B_priv[32];

	ke_ecdh_private(A_priv, sizeof(A_priv));
	ke_ecdh_private(B_priv, sizeof(B_priv));

	ke_ecdh_public(A_pub, sizeof(A_pub), A_priv, sizeof(A_priv));
	ke_ecdh_public(B_pub, sizeof(B_pub), B_priv, sizeof(B_priv));

	ke_ecdh_shared(A_shared, B_pub, sizeof(B_pub), A_priv, sizeof(A_priv));
	ke_ecdh_shared(B_shared, A_pub, sizeof(A_pub), B_priv, sizeof(B_priv));

	if (!memcmp(A_shared, B_shared, sizeof(A_shared))) {
		puts("Keys match!");
		return 0;
	}

	puts("Keys don't match!");

	return 1;
}

