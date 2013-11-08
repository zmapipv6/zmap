#include "util_test.h"

#include <stdlib.h>
#include <check.h>

int main() {
	int number_failed = 0;
	Suite *util = util_suite();
	SRunner *sr = srunner_create(util);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}