#include <stdio.h>

#include <psec/decode.h>

int main(void) {
	char msg[] = "dGVzdA==";
	char *out = NULL;

	out = decode_buffer_base64(NULL, msg, sizeof(msg) - 1);

	puts(out);

	decode_destroy(out);

	return 0;
}

