#include <stdio.h>

#include <psec/decode.h>

int main(void) {
	unsigned char msg[] = "74657374";
	unsigned char *out = NULL;
	size_t out_len = 4; /* 5 bytes are required (including '\0'). This out_len value will fail. */

	if (!(out = decode_buffer_base16(NULL, &out_len, msg, sizeof(msg) - 1))) {
		puts("Buffer too small.");
		return 1;
	}

	puts((char *) out);

	decode_destroy(out);

	return 0;
}

