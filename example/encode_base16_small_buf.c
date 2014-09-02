#include <stdio.h>

#include <psec/encode.h>

int main(void) {
	unsigned char msg[] = "test";
	unsigned char *out = NULL;
	size_t out_len = 8; /* 9 bytes are required (including '\0'). This out_len value will fail. */

	if (!(out = encode_buffer_base16(NULL, &out_len, msg, sizeof(msg) - 1))) {
		puts("Buffer too small.");
		return 1;
	}

	puts((char *) out);

	encode_destroy(out);

	return 0;
}

