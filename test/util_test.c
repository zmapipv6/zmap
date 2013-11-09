#include "util_test.h"
#include "util.h"

#include <check.h>

static void check_str_arr_eq(const char** expected, const char **actual, int len)
{
	int i;
	for(i = 0; i < len; ++i) {
		ck_assert_str_eq(expected[i], actual[i]);
	}
}

static void check_port_arr_eq(const port_h_t* expected, const port_h_t* actual, int len)
{
	int i;
	for (i = 0; i < len; ++i) {
		ck_assert_int_eq(expected[i], actual[i]);
	}
}

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

START_TEST(test_split_string)
{
	static const char* words[] = { "saddr", "classification", "sport" };

	const char* test_str = "saddr,classification,sport";
	int len = 0;
	char **result;
	split_string(test_str, &len, &result);
	ck_assert_int_eq(3, len);
	check_str_arr_eq(words, (const char **) result, len);
	free(result);

	test_str = "saddr  , classification,     sport";
	split_string(test_str, &len, &result);
	ck_assert_int_eq(3, len);
	check_str_arr_eq(words, (const char **) result, len);	
}
END_TEST

START_TEST(test_parse_range_individual)
{
	port_h_t ports[] = { 1, 2, 5, 6, 7, 80, 443 };
	int ports_len = 7;

	const char* ports_individual[] = { "1", "2", "5", "6", "7", "80", "443" };
	int individual_len = 7;

	port_h_t *result;
	int len, i;
	parse_ranges((char **) ports_individual, individual_len, &result, &len);

	ck_assert_int_eq(len, ports_len);

	for (i = 0; i < ports_len; ++i) {
		ck_assert(ports[i] == result[i]);
	}
	free(result);
}
END_TEST

START_TEST(test_parse_range)
{
	port_h_t ports[] = { 443, 1, 2, 3, 9, 10, 11, 80 };
	int ports_len = 8;

	const char* ports_str_literals[] = { "443", "1-3", "9-11", "80" };
	int strs_length = 4;
	char *strs[strs_length];

	int i;
	for (i = 0; i < 4; ++i) {
		strs[i] = strdup(ports_str_literals[i]);
	}

	port_h_t *result;
	int len;
	parse_ranges(strs, strs_length, &result, &len);

	ck_assert_int_eq(ports_len, len);
	for (i = 0; i < len; ++i) {
		ck_assert_int_eq(ports[i], result[i]);
	}
}
END_TEST

START_TEST(test_parse_ports)
{
	port_h_t ports[] = { 1, 2, 5, 6, 7, 80, 443, 20000 };
	int ports_len = 8;

	char *ports_str = strdup("1-2, 5-7, 80, 443, 20000");
	port_h_t *result;
	int len;

	parse_ports(ports_str, &result, &len);
	ck_assert_int_eq(ports_len, len);
	check_port_arr_eq(ports, result, len);
}
END_TEST


Suite* util_suite()
{
	Suite *s = suite_create("util");
	TCase *tc_core = tcase_create("Core");
	/* Add tests here */
	tcase_add_test(tc_core, test_check_range);
	tcase_add_test(tc_core, test_enforce_range);
	tcase_add_test(tc_core, test_split_string);
	tcase_add_test(tc_core, test_parse_range_individual);
	tcase_add_test(tc_core, test_parse_range);
	tcase_add_test(tc_core, test_parse_ports);

	suite_add_tcase(s, tc_core);	
	return s;
}
