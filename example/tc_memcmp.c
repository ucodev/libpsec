#include <stdio.h>

#include <psec/tc.h>

int main(void) {
	char test_1[9] = "testing!";
	char test_2[9] = "testing!";
	char test_3[9] = "testing#";
	char test_4[9] = "tasting!";

	printf("%d\n", tc_memcmp(test_1, test_2, sizeof(test_1)));
	printf("%d\n", tc_memcmp(test_1, test_3, sizeof(test_1)));
	printf("%d\n", tc_memcmp(test_1, test_4, sizeof(test_1)));

	return 0;
}

