#include <stdio.h>

#include <psec/encode.h>
#include <psec/generate.h>

int main(void) {
	unsigned char result[32], encoded_result[32 * 2 + 1];
	size_t out_len = 0;

	generate_bytes_random(result, 32);
	encode_buffer_base16(encoded_result, &out_len, result, 32);

	puts((char *) encoded_result);

	return 0;
}

