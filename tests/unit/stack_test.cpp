// ATF unit tests for pure helpers from lib/stack.cpp.
//
// Uses real StackPure:: symbols from lib/stack_pure.cpp.

#include <atf-c++.hpp>
#include <map>
#include <string>
#include <vector>

#include "stack_pure.h"
#include "err.h"

using StackPure::ipFromCidr;
using StackPure::buildHostsEntries;
using StackPure::topoSort;
using StackPure::validateStackName;
using StackPure::validateStackIp;
using StackEntry = StackPure::StackEntry;

static int indexOf(const std::vector<StackEntry> &v, const std::string &name) {
	for (size_t i = 0; i < v.size(); i++)
		if (v[i].name == name) return (int)i;
	return -1;
}

ATF_TEST_CASE_WITHOUT_HEAD(ipFromCidr_with_prefix);
ATF_TEST_CASE_BODY(ipFromCidr_with_prefix)
{
	ATF_REQUIRE_EQ(ipFromCidr("192.168.1.50/24"), "192.168.1.50");
	ATF_REQUIRE_EQ(ipFromCidr("10.0.0.1/8"), "10.0.0.1");
}

ATF_TEST_CASE_WITHOUT_HEAD(ipFromCidr_without_prefix);
ATF_TEST_CASE_BODY(ipFromCidr_without_prefix)
{
	ATF_REQUIRE_EQ(ipFromCidr("192.168.1.50"), "192.168.1.50");
}

ATF_TEST_CASE_WITHOUT_HEAD(ipFromCidr_empty);
ATF_TEST_CASE_BODY(ipFromCidr_empty)
{
	ATF_REQUIRE_EQ(ipFromCidr(""), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(ipFromCidr_ipv6);
ATF_TEST_CASE_BODY(ipFromCidr_ipv6)
{
	ATF_REQUIRE_EQ(ipFromCidr("fd00::1/64"), "fd00::1");
}

ATF_TEST_CASE_WITHOUT_HEAD(buildHosts_empty);
ATF_TEST_CASE_BODY(buildHosts_empty)
{
	ATF_REQUIRE_EQ(buildHostsEntries({}), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(buildHosts_single);
ATF_TEST_CASE_BODY(buildHosts_single)
{
	ATF_REQUIRE_EQ(buildHostsEntries({{"web", "10.0.0.10"}}), "10.0.0.10 web\n");
}

ATF_TEST_CASE_WITHOUT_HEAD(buildHosts_sorted_by_name);
ATF_TEST_CASE_BODY(buildHosts_sorted_by_name)
{
	std::map<std::string, std::string> m = {
		{"web", "10.0.0.30"},
		{"db",  "10.0.0.20"},
		{"app", "10.0.0.10"},
	};
	auto out = buildHostsEntries(m);
	ATF_REQUIRE_EQ(out,
		"10.0.0.10 app\n"
		"10.0.0.20 db\n"
		"10.0.0.30 web\n");
}

// ===================================================================
// 1.1.25: validateStackName / validateStackIp — the fields that reach a
// root-run `sh -c` fragment (hosts/resolv.conf injection) and the
// `dns-<network>` root-managed config dir.
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(validateStackName_typical_accepted);
ATF_TEST_CASE_BODY(validateStackName_typical_accepted)
{
	ATF_REQUIRE_EQ(validateStackName("web"), "");
	ATF_REQUIRE_EQ(validateStackName("db-primary"), "");
	ATF_REQUIRE_EQ(validateStackName("app.internal_1"), "");
	ATF_REQUIRE_EQ(validateStackName("a..b"), "");   // one component, no '/'
}

ATF_TEST_CASE_WITHOUT_HEAD(validateStackName_injection_rejected);
ATF_TEST_CASE_BODY(validateStackName_injection_rejected)
{
	// Closes the single-quoted printf and runs a command as root.
	ATF_REQUIRE(!validateStackName("x';touch /tmp/pwned;'").empty());
	ATF_REQUIRE(!validateStackName("x\"y").empty());
	ATF_REQUIRE(!validateStackName("x`id`").empty());
	ATF_REQUIRE(!validateStackName("x$(id)").empty());
	ATF_REQUIRE(!validateStackName("x\\y").empty());
	ATF_REQUIRE(!validateStackName("x\ny").empty());
	ATF_REQUIRE(!validateStackName("x y").empty());
	// Path traversal out of the dns-<name> config dir.
	ATF_REQUIRE(!validateStackName("../../../etc/cron.d").empty());
	ATF_REQUIRE(!validateStackName("a/b").empty());
	ATF_REQUIRE(!validateStackName("..").empty());
	ATF_REQUIRE(!validateStackName(".").empty());
	ATF_REQUIRE(!validateStackName("").empty());
	ATF_REQUIRE(!validateStackName("-leading").empty());
	ATF_REQUIRE(!validateStackName(std::string(65, 'a')).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(validateStackIp_typical_accepted);
ATF_TEST_CASE_BODY(validateStackIp_typical_accepted)
{
	ATF_REQUIRE_EQ(validateStackIp("10.0.0.5"), "");
	ATF_REQUIRE_EQ(validateStackIp("10.0.0.5/24"), "");      // CIDR tolerated
	ATF_REQUIRE_EQ(validateStackIp("fd00::1"), "");
	ATF_REQUIRE_EQ(validateStackIp("fd00::1/64"), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(validateStackIp_injection_rejected);
ATF_TEST_CASE_BODY(validateStackIp_injection_rejected)
{
	ATF_REQUIRE(!validateStackIp("1.1.1.1'; reboot;'").empty());
	ATF_REQUIRE(!validateStackIp("1.1.1.1\n").empty());
	ATF_REQUIRE(!validateStackIp("1.1.1.1 evil").empty());
	ATF_REQUIRE(!validateStackIp("256.0.0.1").empty());   // charset ok, inet_pton fails
	ATF_REQUIRE(!validateStackIp("not-an-ip").empty());
	ATF_REQUIRE(!validateStackIp("").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_empty);
ATF_TEST_CASE_BODY(topoSort_empty)
{
	auto out = topoSort<StackEntry>({});
	ATF_REQUIRE_EQ(out.size(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_no_deps);
ATF_TEST_CASE_BODY(topoSort_no_deps)
{
	std::vector<StackEntry> in = { {"a", {}}, {"b", {}}, {"c", {}} };
	auto out = topoSort(in);
	ATF_REQUIRE_EQ(out.size(), 3u);
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_linear_chain);
ATF_TEST_CASE_BODY(topoSort_linear_chain)
{
	std::vector<StackEntry> in = {
		{"web", {"app"}},
		{"app", {"db"}},
		{"db",  {}},
	};
	auto out = topoSort(in);
	ATF_REQUIRE_EQ(out.size(), 3u);
	ATF_REQUIRE(indexOf(out, "db")  < indexOf(out, "app"));
	ATF_REQUIRE(indexOf(out, "app") < indexOf(out, "web"));
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_diamond);
ATF_TEST_CASE_BODY(topoSort_diamond)
{
	std::vector<StackEntry> in = {
		{"web",   {"app", "cache"}},
		{"app",   {"db"}},
		{"cache", {"db"}},
		{"db",    {}},
	};
	auto out = topoSort(in);
	ATF_REQUIRE_EQ(out.size(), 4u);
	int db = indexOf(out, "db");
	int app = indexOf(out, "app");
	int cache = indexOf(out, "cache");
	int web = indexOf(out, "web");
	ATF_REQUIRE(db < app);
	ATF_REQUIRE(db < cache);
	ATF_REQUIRE(app < web);
	ATF_REQUIRE(cache < web);
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_cycle_throws);
ATF_TEST_CASE_BODY(topoSort_cycle_throws)
{
	std::vector<StackEntry> in = {
		{"a", {"b"}},
		{"b", {"a"}},
	};
	ATF_REQUIRE_THROW(Exception, topoSort(in));
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_self_cycle_throws);
ATF_TEST_CASE_BODY(topoSort_self_cycle_throws)
{
	std::vector<StackEntry> in = {{"a", {"a"}}};
	ATF_REQUIRE_THROW(Exception, topoSort(in));
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_unknown_dep_throws);
ATF_TEST_CASE_BODY(topoSort_unknown_dep_throws)
{
	std::vector<StackEntry> in = {{"a", {"ghost"}}};
	ATF_REQUIRE_THROW(Exception, topoSort(in));
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_duplicate_name_throws);
ATF_TEST_CASE_BODY(topoSort_duplicate_name_throws)
{
	std::vector<StackEntry> in = { {"a", {}}, {"a", {}} };
	ATF_REQUIRE_THROW(Exception, topoSort(in));
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_three_node_cycle_throws);
ATF_TEST_CASE_BODY(topoSort_three_node_cycle_throws)
{
	std::vector<StackEntry> in = {
		{"a", {"c"}},
		{"b", {"a"}},
		{"c", {"b"}},
	};
	ATF_REQUIRE_THROW(Exception, topoSort(in));
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_disconnected_components);
ATF_TEST_CASE_BODY(topoSort_disconnected_components)
{
	std::vector<StackEntry> in = {
		{"a", {"b"}},
		{"b", {}},
		{"x", {"y"}},
		{"y", {}},
	};
	auto out = topoSort(in);
	ATF_REQUIRE_EQ(out.size(), 4u);
	ATF_REQUIRE(indexOf(out, "b") < indexOf(out, "a"));
	ATF_REQUIRE(indexOf(out, "y") < indexOf(out, "x"));
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, ipFromCidr_with_prefix);
	ATF_ADD_TEST_CASE(tcs, ipFromCidr_without_prefix);
	ATF_ADD_TEST_CASE(tcs, ipFromCidr_empty);
	ATF_ADD_TEST_CASE(tcs, ipFromCidr_ipv6);
	ATF_ADD_TEST_CASE(tcs, buildHosts_empty);
	ATF_ADD_TEST_CASE(tcs, buildHosts_single);
	ATF_ADD_TEST_CASE(tcs, buildHosts_sorted_by_name);
	ATF_ADD_TEST_CASE(tcs, topoSort_empty);
	ATF_ADD_TEST_CASE(tcs, topoSort_no_deps);
	ATF_ADD_TEST_CASE(tcs, topoSort_linear_chain);
	ATF_ADD_TEST_CASE(tcs, topoSort_diamond);
	ATF_ADD_TEST_CASE(tcs, topoSort_cycle_throws);
	ATF_ADD_TEST_CASE(tcs, topoSort_self_cycle_throws);
	ATF_ADD_TEST_CASE(tcs, topoSort_unknown_dep_throws);
	ATF_ADD_TEST_CASE(tcs, topoSort_duplicate_name_throws);
	ATF_ADD_TEST_CASE(tcs, topoSort_three_node_cycle_throws);
	ATF_ADD_TEST_CASE(tcs, topoSort_disconnected_components);
	ATF_ADD_TEST_CASE(tcs, validateStackName_typical_accepted);
	ATF_ADD_TEST_CASE(tcs, validateStackName_injection_rejected);
	ATF_ADD_TEST_CASE(tcs, validateStackIp_typical_accepted);
	ATF_ADD_TEST_CASE(tcs, validateStackIp_injection_rejected);
}
