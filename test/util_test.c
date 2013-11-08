#include "util_test.h"

#include <check.h>

START_TEST (test_enforce_range)
{
	ck_assert_int_eq(4, 4);
}
END_TEST

Suite* util_suite()
{
	Suite *s = suite_create("util");
	TCase *tc_core = tcase_create("Core");
	/* Add tests here */
	tcase_add_test(tc_core, test_enforce_range);

	suite_add_tcase(s, tc_core);	
	return s;
}
