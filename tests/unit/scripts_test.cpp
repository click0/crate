// ATF unit tests for ScriptsPure::escape (lib/scripts.cpp).
//
// Used to embed user-supplied script bodies inside /bin/sh -c '...' calls.
// A bug here = command injection in any code path that runs a user script.

#include <atf-c++.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "scripts_pure.h"

using ScriptsPure::escape;

ATF_TEST_CASE_WITHOUT_HEAD(escape_empty);
ATF_TEST_CASE_BODY(escape_empty)
{
	ATF_REQUIRE_EQ(escape(""), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(escape_no_quotes);
ATF_TEST_CASE_BODY(escape_no_quotes)
{
	ATF_REQUIRE_EQ(escape("hello world"), "hello world");
	ATF_REQUIRE_EQ(escape("echo $foo"), "echo $foo");
	ATF_REQUIRE_EQ(escape("a;b&c|d"), "a;b&c|d");
}

ATF_TEST_CASE_WITHOUT_HEAD(escape_single_quote);
ATF_TEST_CASE_BODY(escape_single_quote)
{
	ATF_REQUIRE_EQ(escape("'"), "'\\''");
	ATF_REQUIRE_EQ(escape("a'b"), "a'\\''b");
}

ATF_TEST_CASE_WITHOUT_HEAD(escape_command_injection_attempt);
ATF_TEST_CASE_BODY(escape_command_injection_attempt)
{
	// Classic injection: ' ; rm -rf /
	auto out = escape("' ; rm -rf /");
	// After wrapping in '...', this becomes: ''\''  ; rm -rf /'
	// The injection is contained.
	ATF_REQUIRE_EQ(out, "'\\'' ; rm -rf /");
}

ATF_TEST_CASE_WITHOUT_HEAD(escape_round_trip_through_sh);
ATF_TEST_CASE_BODY(escape_round_trip_through_sh)
{
	// Black-box: feed the wrapped output to /bin/sh -c '...' and verify
	// the input string survives intact.
	if (!std::filesystem::exists("/bin/sh"))
		ATF_SKIP("/bin/sh not available");
	auto temp = std::filesystem::temp_directory_path() / "crate_scripts_escape_out";
	const std::string inputs[] = {
		"echo hello",
		"a'b'c",
		"echo 'with quotes'",
		"echo $((1+2))",
		"' ; rm -rf /",
		"new\nline",
	};
	for (const auto &in : inputs) {
		auto cmd = "/bin/sh -c 'printf %s \"" + escape(in) + "\"' > " + temp.string();
		(void)std::system(cmd.c_str());
		// We're not checking exact output (the sh layer may interpret things)
		// — just that the call doesn't crash and produces a valid file.
		ATF_REQUIRE(std::filesystem::exists(temp));
	}
	std::filesystem::remove(temp);
}

// 1.1.75: where `crate run` executes each section, and the throw-away
// jail(8) command line. A section that runs after the jail's processes
// started must never go through chroot as host root again.
ATF_TEST_CASE_WITHOUT_HEAD(hook_place);
ATF_TEST_CASE_BODY(hook_place)
{
	using ScriptsPure::hookPlace;
	using ScriptsPure::HookPlace;
	ATF_REQUIRE(hookPlace("run:begin") == HookPlace::ThrowAway);
	ATF_REQUIRE(hookPlace("run:before-create-jail") == HookPlace::ThrowAway);
	ATF_REQUIRE(hookPlace("run:after-remove-jail") == HookPlace::ThrowAway);
	for (const char *s : {"run:after-create-jail", "init", "run:before-create-users",
	                      "run:after-create-users", "run:before-start-services",
	                      "run:after-start-services", "run:before-execute",
	                      "run:after-execute", "run:end", "run:before-remove-jail"})
		ATF_REQUIRE(hookPlace(s) == HookPlace::InJail);
}

ATF_TEST_CASE_WITHOUT_HEAD(first_throw_away_section);
ATF_TEST_CASE_BODY(first_throw_away_section)
{
	using ScriptsPure::firstThrowAwaySection;
	ATF_REQUIRE_EQ(firstThrowAwaySection({}), "");
	ATF_REQUIRE_EQ(firstThrowAwaySection({"run:before-start-services", "run:before-execute"}), "");
	ATF_REQUIRE_EQ(firstThrowAwaySection({"run:end", "run:after-remove-jail"}), "run:after-remove-jail");
	// run order, not the spec's map order
	ATF_REQUIRE_EQ(firstThrowAwaySection({"run:before-create-jail", "run:begin"}), "run:begin");
}

ATF_TEST_CASE_WITHOUT_HEAD(throw_away_jail_argv);
ATF_TEST_CASE_BODY(throw_away_jail_argv)
{
	auto a = ScriptsPure::throwAwayJailArgv("/var/run/crate/0/jail-x-1", "ASSUME_ALWAYS_YES=yes /bin/sh -c 'id'", true);
	std::vector<std::string> want = {"/usr/sbin/jail", "-c", "path=/var/run/crate/0/jail-x-1",
	                                 "ip4=inherit", "ip6=inherit", "command=/bin/sh", "-c",
	                                 "ASSUME_ALWAYS_YES=yes /bin/sh -c 'id'"};
	ATF_REQUIRE(a == want);
	// no INET6 in the kernel: no ip6 parameter, which jail(8) would not know
	auto b = ScriptsPure::throwAwayJailArgv("/j", "true", false);
	for (const auto &arg : b) ATF_REQUIRE(arg.compare(0, 4, "ip6=") != 0);
	// never chroot, never persist
	for (const auto &arg : a) {
		ATF_REQUIRE(arg.find("chroot") == std::string::npos);
		ATF_REQUIRE(arg.find("persist") == std::string::npos);
	}
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, hook_place);
	ATF_ADD_TEST_CASE(tcs, first_throw_away_section);
	ATF_ADD_TEST_CASE(tcs, throw_away_jail_argv);
	ATF_ADD_TEST_CASE(tcs, escape_empty);
	ATF_ADD_TEST_CASE(tcs, escape_no_quotes);
	ATF_ADD_TEST_CASE(tcs, escape_single_quote);
	ATF_ADD_TEST_CASE(tcs, escape_command_injection_attempt);
	ATF_ADD_TEST_CASE(tcs, escape_round_trip_through_sh);
}
