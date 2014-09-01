#include <stdio.h>

#include <psec/tc.h>

int main(void) {
	char test[32];

	tc_memset(test, 'A', 31);

	test[31] = 0;

	puts(test);

	return 0;
}

