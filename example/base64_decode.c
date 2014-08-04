#include <stdio.h>

#include <psec/decode.h>

int main(void) {
	char msg[] = "dGVzdA==";
	char *out = NULL;
	size_t out_len = 0;

	out = decode_buffer_base64(NULL, &out_len, msg, sizeof(msg) - 1);

	puts(out);

	decode_destroy(out);

	return 0;
}

