#!/bin/sh
# ATF functional test skeleton for 'crate info'
#
# Run: cd tests && kyua test

. $(atf_get_srcdir)/../../tests/functional/test_helpers.sh 2>/dev/null || true

atf_test_case crate_binary_exists
crate_binary_exists_head()
{
	atf_set "descr" "Check that crate binary is present"
}
crate_binary_exists_body()
{
	# Adjust path as needed for the test environment
	if [ ! -x /usr/local/bin/crate ]; then
		atf_skip "crate binary not installed"
	fi
	atf_check -s exit:0 -o ignore /usr/local/bin/crate info -v
}

atf_test_case crate_help
crate_help_head()
{
	atf_set "descr" "crate --help exits successfully"
}
crate_help_body()
{
	if [ ! -x /usr/local/bin/crate ]; then
		atf_skip "crate binary not installed"
	fi
	atf_check -s exit:0 -o match:"usage" /usr/local/bin/crate --help
}

atf_init_test_cases()
{
	atf_add_test_case crate_binary_exists
	atf_add_test_case crate_help
}
