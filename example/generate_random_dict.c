#include <stdio.h>

#include <psec/generate.h>

int main(void) {
	unsigned char result[33];
	unsigned char dict[10] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
	size_t out_len = 0;

	generate_dict_random(result, 32, dict, sizeof(dict));
	result[32] = 0;

	puts((char *) result);

	return 0;
}

