// ATF unit tests for AuditPure (lib/audit_pure.cpp).

#include <atf-c++.hpp>
#include <regex>
#include <string>

#include "audit_pure.h"
#include "args.h"

using AuditPure::Event;
using AuditPure::renderJson;
using AuditPure::pickTarget;
using AuditPure::formatTimestampUtc;
using AuditPure::joinArgv;

static Event mkEv() {
	Event ev;
	ev.ts      = "2026-05-01T20:55:01Z";
	ev.pid     = 12345;
	ev.uid     = 1000;
	ev.euid    = 0;
	ev.gid     = 1000;
	ev.egid    = 0;
	ev.user    = "alice";
	ev.host    = "build-server";
	ev.cmd     = "create";
	ev.target  = "spec.yml";
	ev.argv    = "'crate' 'create' '-s' 'spec.yml'";
	ev.outcome = "started";
	return ev;
}

// ===================================================================
// renderJson — shape + escapes
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(json_basic_shape);
ATF_TEST_CASE_BODY(json_basic_shape)
{
	auto j = renderJson(mkEv());
	// All fields present with correct types
	ATF_REQUIRE(j.find("\"ts\":\"2026-05-01T20:55:01Z\"") != std::string::npos);
	ATF_REQUIRE(j.find("\"pid\":12345")  != std::string::npos);
	ATF_REQUIRE(j.find("\"uid\":1000")   != std::string::npos);
	ATF_REQUIRE(j.find("\"euid\":0")     != std::string::npos);
	ATF_REQUIRE(j.find("\"user\":\"alice\"")    != std::string::npos);
	ATF_REQUIRE(j.find("\"cmd\":\"create\"")    != std::string::npos);
	ATF_REQUIRE(j.find("\"outcome\":\"started\"") != std::string::npos);
	// Single-line, no embedded newline
	ATF_REQUIRE(j.find('\n') == std::string::npos);
	// Single object
	ATF_REQUIRE(j.front() == '{');
	ATF_REQUIRE(j.back()  == '}');
}

ATF_TEST_CASE_WITHOUT_HEAD(json_escapes_quote_backslash);
ATF_TEST_CASE_BODY(json_escapes_quote_backslash)
{
	auto ev = mkEv();
	ev.target = "a\"b";
	auto j = renderJson(ev);
	// "a\"b" must appear escaped, not raw
	ATF_REQUIRE(j.find("\"target\":\"a\\\"b\"") != std::string::npos);

	ev.target = "back\\slash";
	auto j2 = renderJson(ev);
	ATF_REQUIRE(j2.find("\"target\":\"back\\\\slash\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(json_escapes_control_chars);
ATF_TEST_CASE_BODY(json_escapes_control_chars)
{
	auto ev = mkEv();
	ev.target = "a\nb\tc\rd";
	auto j = renderJson(ev);
	ATF_REQUIRE(j.find("a\\nb\\tc\\rd") != std::string::npos);
	// No raw control chars survive in the JSON
	ATF_REQUIRE(j.find('\n') == std::string::npos);
	ATF_REQUIRE(j.find('\t') == std::string::npos);
	ATF_REQUIRE(j.find('\r') == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(json_escapes_low_unicode);
ATF_TEST_CASE_BODY(json_escapes_low_unicode)
{
	auto ev = mkEv();
	ev.target = std::string("a\x01""b", 3);
	auto j = renderJson(ev);
	ATF_REQUIRE(j.find("\\u0001") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(json_passes_utf8);
ATF_TEST_CASE_BODY(json_passes_utf8)
{
	auto ev = mkEv();
	ev.user = "Олексій";  // UTF-8
	auto j = renderJson(ev);
	// UTF-8 above 0x7F passes through
	ATF_REQUIRE(j.find("Олексій") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(json_argv_with_special_chars);
ATF_TEST_CASE_BODY(json_argv_with_special_chars)
{
	auto ev = mkEv();
	ev.argv = "crate run -- 'echo \"hi\"'";
	auto j = renderJson(ev);
	// Inner quotes must be escaped
	ATF_REQUIRE(j.find("\\\"hi\\\"") != std::string::npos);
}

// ===================================================================
// pickTarget — Args → target string
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(pickTarget_create_uses_spec);
ATF_TEST_CASE_BODY(pickTarget_create_uses_spec)
{
	Args a; a.cmd = CmdCreate; a.createSpec = "/path/spec.yml";
	ATF_REQUIRE_EQ(pickTarget(a), "/path/spec.yml");
}

ATF_TEST_CASE_WITHOUT_HEAD(pickTarget_create_falls_back_to_template);
ATF_TEST_CASE_BODY(pickTarget_create_falls_back_to_template)
{
	Args a; a.cmd = CmdCreate; a.createTemplate = "base";
	ATF_REQUIRE_EQ(pickTarget(a), "base");
}

ATF_TEST_CASE_WITHOUT_HEAD(pickTarget_run_uses_file);
ATF_TEST_CASE_BODY(pickTarget_run_uses_file)
{
	Args a; a.cmd = CmdRun; a.runCrateFile = "/x.crate";
	ATF_REQUIRE_EQ(pickTarget(a), "/x.crate");
}

ATF_TEST_CASE_WITHOUT_HEAD(pickTarget_snapshot_dataset_plus_name);
ATF_TEST_CASE_BODY(pickTarget_snapshot_dataset_plus_name)
{
	Args a; a.cmd = CmdSnapshot; a.snapshotDataset = "tank/jails/web";
	a.snapshotName = "v1";
	ATF_REQUIRE_EQ(pickTarget(a), "tank/jails/web@v1");

	Args b; b.cmd = CmdSnapshot; b.snapshotDataset = "tank/jails/web";
	ATF_REQUIRE_EQ(pickTarget(b), "tank/jails/web");
}

ATF_TEST_CASE_WITHOUT_HEAD(pickTarget_no_target_for_list_clean);
ATF_TEST_CASE_BODY(pickTarget_no_target_for_list_clean)
{
	Args a; a.cmd = CmdList;  ATF_REQUIRE_EQ(pickTarget(a), "");
	Args b; b.cmd = CmdClean; ATF_REQUIRE_EQ(pickTarget(b), "");
	Args c; c.cmd = CmdNone;  ATF_REQUIRE_EQ(pickTarget(c), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(pickTarget_target_only_commands);
ATF_TEST_CASE_BODY(pickTarget_target_only_commands)
{
	{ Args a; a.cmd = CmdInfo;    a.infoTarget    = "x"; ATF_REQUIRE_EQ(pickTarget(a), "x"); }
	{ Args a; a.cmd = CmdConsole; a.consoleTarget = "x"; ATF_REQUIRE_EQ(pickTarget(a), "x"); }
	{ Args a; a.cmd = CmdExport;  a.exportTarget  = "x"; ATF_REQUIRE_EQ(pickTarget(a), "x"); }
	{ Args a; a.cmd = CmdImport;  a.importFile    = "x"; ATF_REQUIRE_EQ(pickTarget(a), "x"); }
	{ Args a; a.cmd = CmdStats;   a.statsTarget   = "x"; ATF_REQUIRE_EQ(pickTarget(a), "x"); }
	{ Args a; a.cmd = CmdLogs;    a.logsTarget    = "x"; ATF_REQUIRE_EQ(pickTarget(a), "x"); }
	{ Args a; a.cmd = CmdStop;    a.stopTarget    = "x"; ATF_REQUIRE_EQ(pickTarget(a), "x"); }
	{ Args a; a.cmd = CmdRestart; a.restartTarget = "x"; ATF_REQUIRE_EQ(pickTarget(a), "x"); }
}

// ===================================================================
// formatTimestampUtc
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(timestamp_format);
ATF_TEST_CASE_BODY(timestamp_format)
{
	// Canonical UNIX epoch — trivial to verify.
	ATF_REQUIRE_EQ(formatTimestampUtc(0), "1970-01-01T00:00:00Z");
	// Y2K boundary (2000-01-01 00:00:00 UTC = 946684800)
	ATF_REQUIRE_EQ(formatTimestampUtc(946684800), "2000-01-01T00:00:00Z");
}

ATF_TEST_CASE_WITHOUT_HEAD(timestamp_pattern);
ATF_TEST_CASE_BODY(timestamp_pattern)
{
	auto s = formatTimestampUtc(::time(nullptr));
	std::regex pat(R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$)");
	ATF_REQUIRE(std::regex_match(s, pat));
}

// ===================================================================
// joinArgv
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(joinArgv_basic);
ATF_TEST_CASE_BODY(joinArgv_basic)
{
	char a[] = "crate"; char b[] = "create"; char c[] = "-s"; char d[] = "spec.yml";
	char *argv[] = {a, b, c, d};
	auto s = joinArgv(4, argv);
	ATF_REQUIRE_EQ(s, "'crate' 'create' '-s' 'spec.yml'");
}

ATF_TEST_CASE_WITHOUT_HEAD(joinArgv_quotes_special);
ATF_TEST_CASE_BODY(joinArgv_quotes_special)
{
	char a[] = "crate"; char b[] = "$(rm -rf /)";
	char *argv[] = {a, b};
	auto s = joinArgv(2, argv);
	// Each arg single-quoted so it can be safely replayed.
	ATF_REQUIRE(s.find("'$(rm -rf /)'") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(joinArgv_empty);
ATF_TEST_CASE_BODY(joinArgv_empty)
{
	ATF_REQUIRE_EQ(joinArgv(0, nullptr), "");
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, json_basic_shape);
	ATF_ADD_TEST_CASE(tcs, json_escapes_quote_backslash);
	ATF_ADD_TEST_CASE(tcs, json_escapes_control_chars);
	ATF_ADD_TEST_CASE(tcs, json_escapes_low_unicode);
	ATF_ADD_TEST_CASE(tcs, json_passes_utf8);
	ATF_ADD_TEST_CASE(tcs, json_argv_with_special_chars);
	ATF_ADD_TEST_CASE(tcs, pickTarget_create_uses_spec);
	ATF_ADD_TEST_CASE(tcs, pickTarget_create_falls_back_to_template);
	ATF_ADD_TEST_CASE(tcs, pickTarget_run_uses_file);
	ATF_ADD_TEST_CASE(tcs, pickTarget_snapshot_dataset_plus_name);
	ATF_ADD_TEST_CASE(tcs, pickTarget_no_target_for_list_clean);
	ATF_ADD_TEST_CASE(tcs, pickTarget_target_only_commands);
	ATF_ADD_TEST_CASE(tcs, timestamp_format);
	ATF_ADD_TEST_CASE(tcs, timestamp_pattern);
	ATF_ADD_TEST_CASE(tcs, joinArgv_basic);
	ATF_ADD_TEST_CASE(tcs, joinArgv_quotes_special);
	ATF_ADD_TEST_CASE(tcs, joinArgv_empty);
}
