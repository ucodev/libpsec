#include <stdio.h>

#include <psec/encode.h>

int main(void) {
	unsigned char msg[] = "test";
	unsigned char *out = NULL;
	size_t out_len = 0;

	out = encode_buffer_base16(NULL, &out_len, msg, sizeof(msg) - 1);

	puts((char *) out);

	encode_destroy(out);

	return 0;
}

