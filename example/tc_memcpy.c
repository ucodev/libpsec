#include <stdio.h>

#include <psec/tc.h>

int main(void) {
	char src[9] = "testing!";
	char dest[9];

	tc_memcpy(dest, src, sizeof(src));

	puts(dest);

	return 0;
}

