// ATF unit tests for pure helpers from lib/stack.cpp
//   - ipFromCidr
//   - buildHostsEntries
//   - topoSort (Kahn's algorithm with cycle/duplicate/missing-dep detection)
//
// Build:
//   c++ -std=c++17 -o tests/unit/stack_test \
//       tests/unit/stack_test.cpp -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <map>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// ===================================================================
// Local copies of pure helpers from lib/stack.cpp
// (ERR macro replaced with std::runtime_error throw)
// ===================================================================

#define ERR(msg) do { std::ostringstream _e; _e << msg; throw std::runtime_error(_e.str()); } while (0)

static std::string ipFromCidr(const std::string &cidr) {
	auto pos = cidr.find('/');
	return pos != std::string::npos ? cidr.substr(0, pos) : cidr;
}

static std::string buildHostsEntries(const std::map<std::string, std::string> &nameToIp) {
	std::ostringstream ss;
	for (auto &kv : nameToIp)
		ss << kv.second << " " << kv.first << "\n";
	return ss.str();
}

// Minimal StackEntry for topoSort tests (only fields the algorithm needs)
struct StackEntry {
	std::string name;
	std::vector<std::string> depends;
};

static std::vector<StackEntry> topoSort(const std::vector<StackEntry> &entries) {
	std::map<std::string, size_t> nameIdx;
	for (size_t i = 0; i < entries.size(); i++) {
		if (nameIdx.count(entries[i].name))
			ERR("duplicate container name '" << entries[i].name << "' in stack file");
		nameIdx[entries[i].name] = i;
	}

	for (auto &e : entries)
		for (auto &d : e.depends)
			if (!nameIdx.count(d))
				ERR("container '" << e.name << "' depends on unknown container '" << d << "'");

	size_t n = entries.size();
	std::vector<int> inDeg(n, 0);
	std::vector<std::vector<size_t>> adj(n);

	for (size_t i = 0; i < n; i++) {
		for (auto &d : entries[i].depends) {
			size_t di = nameIdx[d];
			adj[di].push_back(i);
			inDeg[i]++;
		}
	}

	std::queue<size_t> q;
	for (size_t i = 0; i < n; i++)
		if (inDeg[i] == 0)
			q.push(i);

	std::vector<StackEntry> sorted;
	sorted.reserve(n);
	while (!q.empty()) {
		size_t cur = q.front();
		q.pop();
		sorted.push_back(entries[cur]);
		for (auto next : adj[cur]) {
			if (--inDeg[next] == 0)
				q.push(next);
		}
	}

	if (sorted.size() != n)
		ERR("circular dependency detected in stack file");

	return sorted;
}

// Helper: locate the index of `name` in a sorted result
static int indexOf(const std::vector<StackEntry> &v, const std::string &name) {
	for (size_t i = 0; i < v.size(); i++)
		if (v[i].name == name) return (int)i;
	return -1;
}

// ===================================================================
// Tests: ipFromCidr
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(ipFromCidr_with_prefix);
ATF_TEST_CASE_BODY(ipFromCidr_with_prefix)
{
	ATF_REQUIRE_EQ(ipFromCidr("192.168.1.50/24"), "192.168.1.50");
	ATF_REQUIRE_EQ(ipFromCidr("10.0.0.1/8"), "10.0.0.1");
}

ATF_TEST_CASE_WITHOUT_HEAD(ipFromCidr_without_prefix);
ATF_TEST_CASE_BODY(ipFromCidr_without_prefix)
{
	// No slash — return as-is
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
	// Function is naive — splits on first '/', so IPv6 with prefix works too
	ATF_REQUIRE_EQ(ipFromCidr("fd00::1/64"), "fd00::1");
}

// ===================================================================
// Tests: buildHostsEntries — emits "<ip> <name>\n", sorted by name (std::map)
// ===================================================================

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
	// std::map iterates in key order — output must be deterministic
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
// Tests: topoSort — Kahn's algorithm
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_empty);
ATF_TEST_CASE_BODY(topoSort_empty)
{
	auto out = topoSort({});
	ATF_REQUIRE_EQ(out.size(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_no_deps);
ATF_TEST_CASE_BODY(topoSort_no_deps)
{
	std::vector<StackEntry> in = {
		{"a", {}}, {"b", {}}, {"c", {}},
	};
	auto out = topoSort(in);
	ATF_REQUIRE_EQ(out.size(), 3u);
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_linear_chain);
ATF_TEST_CASE_BODY(topoSort_linear_chain)
{
	// web -> app -> db
	// Result must place db before app before web
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
	// db is a shared dep of cache and app; web depends on both
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
	// a -> b -> a
	std::vector<StackEntry> in = {
		{"a", {"b"}},
		{"b", {"a"}},
	};
	ATF_REQUIRE_THROW(std::runtime_error, topoSort(in));
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_self_cycle_throws);
ATF_TEST_CASE_BODY(topoSort_self_cycle_throws)
{
	std::vector<StackEntry> in = {{"a", {"a"}}};
	ATF_REQUIRE_THROW(std::runtime_error, topoSort(in));
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_unknown_dep_throws);
ATF_TEST_CASE_BODY(topoSort_unknown_dep_throws)
{
	std::vector<StackEntry> in = {{"a", {"ghost"}}};
	ATF_REQUIRE_THROW(std::runtime_error, topoSort(in));
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_duplicate_name_throws);
ATF_TEST_CASE_BODY(topoSort_duplicate_name_throws)
{
	std::vector<StackEntry> in = {
		{"a", {}},
		{"a", {}},
	};
	ATF_REQUIRE_THROW(std::runtime_error, topoSort(in));
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_three_node_cycle_throws);
ATF_TEST_CASE_BODY(topoSort_three_node_cycle_throws)
{
	// a -> b -> c -> a
	std::vector<StackEntry> in = {
		{"a", {"c"}},
		{"b", {"a"}},
		{"c", {"b"}},
	};
	ATF_REQUIRE_THROW(std::runtime_error, topoSort(in));
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_disconnected_components);
ATF_TEST_CASE_BODY(topoSort_disconnected_components)
{
	// Two independent chains: a->b and x->y
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

// ===================================================================
// Registration
// ===================================================================

ATF_INIT_TEST_CASES(tcs)
{
	// ipFromCidr
	ATF_ADD_TEST_CASE(tcs, ipFromCidr_with_prefix);
	ATF_ADD_TEST_CASE(tcs, ipFromCidr_without_prefix);
	ATF_ADD_TEST_CASE(tcs, ipFromCidr_empty);
	ATF_ADD_TEST_CASE(tcs, ipFromCidr_ipv6);

	// buildHostsEntries
	ATF_ADD_TEST_CASE(tcs, buildHosts_empty);
	ATF_ADD_TEST_CASE(tcs, buildHosts_single);
	ATF_ADD_TEST_CASE(tcs, buildHosts_sorted_by_name);

	// topoSort
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
}
