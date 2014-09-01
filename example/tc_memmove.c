#include <stdio.h>

#include <psec/tc.h>

int main(void) {
	char test_1[9] = "testing!";
	char test_2[9] = "testing!";

	tc_memmove(test_1, test_1 + 2, 4);
	tc_memmove(test_2 + 2, test_2, 4);

	puts(test_1);
	puts(test_2);

	return 0;
}

