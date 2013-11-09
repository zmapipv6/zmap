#include "util_test.h"
#include "util.h"

#include <check.h>

START_TEST(test_check_range)
{
	ck_assert(check_range(0, 0, 10));
	ck_assert(check_range(10, 0, 10));
	ck_assert(check_range(5, 0, 10));
	ck_assert(!check_range(-1, 0, 10));
	ck_assert(!check_range(11, 0, 10));
}
END_TEST

START_TEST(test_enforce_range)
{
	enforce_range("Valid", 0, 0, 10);
	ck_assert(1);
}
END_TEST

Suite* util_suite()
{
	Suite *s = suite_create("util");
	TCase *tc_core = tcase_create("Core");
	/* Add tests here */
	tcase_add_test(tc_core, test_check_range);
	tcase_add_test(tc_core, test_enforce_range);

	suite_add_tcase(s, tc_core);	
	return s;
}
