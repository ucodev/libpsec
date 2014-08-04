#include <stdio.h>

#include <psec/encode.h>

int main(void) {
	char msg[] = "test";
	char *out = NULL;

	out = encode_buffer_base64(NULL, msg, sizeof(msg) - 1);

	puts(out);

	encode_destroy(out);

	return 0;
}

