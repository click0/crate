// ATF unit tests for pure helpers from cli/args.cpp.
//
// Uses real ArgsPure:: symbols from cli/args_pure.cpp.

#include <atf-c++.hpp>

#include "args_pure.h"

using ArgsPure::strEq;
using ArgsPure::isShort;
using ArgsPure::isLong;
using ArgsPure::isCommand;

ATF_TEST_CASE_WITHOUT_HEAD(strEq_basic);
ATF_TEST_CASE_BODY(strEq_basic)
{
	ATF_REQUIRE(strEq("foo", "foo"));
	ATF_REQUIRE(!strEq("foo", "bar"));
	ATF_REQUIRE(!strEq("foo", "foobar"));
	ATF_REQUIRE(!strEq("foobar", "foo"));
	ATF_REQUIRE(strEq("", ""));
	ATF_REQUIRE(!strEq("", "x"));
}

ATF_TEST_CASE_WITHOUT_HEAD(strEq_case_sensitive);
ATF_TEST_CASE_BODY(strEq_case_sensitive)
{
	ATF_REQUIRE(!strEq("foo", "FOO"));
	ATF_REQUIRE(!strEq("Run", "run"));
}

ATF_TEST_CASE_WITHOUT_HEAD(isShort_letters);
ATF_TEST_CASE_BODY(isShort_letters)
{
	ATF_REQUIRE_EQ(isShort("-h"), 'h');
	ATF_REQUIRE_EQ(isShort("-V"), 'V');
	ATF_REQUIRE_EQ(isShort("-p"), 'p');
	ATF_REQUIRE_EQ(isShort("-Z"), 'Z');
}

ATF_TEST_CASE_WITHOUT_HEAD(isShort_digits);
ATF_TEST_CASE_BODY(isShort_digits)
{
	ATF_REQUIRE_EQ(isShort("-0"), '0');
	ATF_REQUIRE_EQ(isShort("-9"), '9');
}

ATF_TEST_CASE_WITHOUT_HEAD(isShort_rejects_long);
ATF_TEST_CASE_BODY(isShort_rejects_long)
{
	ATF_REQUIRE_EQ(isShort("--help"), 0);
	ATF_REQUIRE_EQ(isShort("-hh"), 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(isShort_rejects_non_dash);
ATF_TEST_CASE_BODY(isShort_rejects_non_dash)
{
	ATF_REQUIRE_EQ(isShort("h"), 0);
	ATF_REQUIRE_EQ(isShort("/h"), 0);
	ATF_REQUIRE_EQ(isShort("+h"), 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(isShort_rejects_punctuation);
ATF_TEST_CASE_BODY(isShort_rejects_punctuation)
{
	ATF_REQUIRE_EQ(isShort("-."), 0);
	ATF_REQUIRE_EQ(isShort("-_"), 0);
	ATF_REQUIRE_EQ(isShort("-?"), 0);
	ATF_REQUIRE_EQ(isShort("--"), 0);
	ATF_REQUIRE_EQ(isShort("-"), 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(isShort_rejects_empty);
ATF_TEST_CASE_BODY(isShort_rejects_empty)
{
	ATF_REQUIRE_EQ(isShort(""), 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(isLong_basic);
ATF_TEST_CASE_BODY(isLong_basic)
{
	auto p = isLong("--help");
	ATF_REQUIRE(p != nullptr);
	ATF_REQUIRE_EQ(std::string(p), "help");
}

ATF_TEST_CASE_WITHOUT_HEAD(isLong_returns_nullptr_for_short);
ATF_TEST_CASE_BODY(isLong_returns_nullptr_for_short)
{
	ATF_REQUIRE_EQ(isLong("-h"), nullptr);
	ATF_REQUIRE_EQ(isLong("h"), nullptr);
}

ATF_TEST_CASE_WITHOUT_HEAD(isLong_returns_nullptr_for_uppercase);
ATF_TEST_CASE_BODY(isLong_returns_nullptr_for_uppercase)
{
	ATF_REQUIRE_EQ(isLong("--Help"), nullptr);
	ATF_REQUIRE_EQ(isLong("--HELP"), nullptr);
}

ATF_TEST_CASE_WITHOUT_HEAD(isLong_accepts_dash);
ATF_TEST_CASE_BODY(isLong_accepts_dash)
{
	auto p = isLong("--no-color");
	ATF_REQUIRE(p != nullptr);
	ATF_REQUIRE_EQ(std::string(p), "no-color");

	auto q = isLong("--log-progress");
	ATF_REQUIRE(q != nullptr);
	ATF_REQUIRE_EQ(std::string(q), "log-progress");
}

ATF_TEST_CASE_WITHOUT_HEAD(isLong_accepts_digits);
ATF_TEST_CASE_BODY(isLong_accepts_digits)
{
	auto p = isLong("--tail10");
	ATF_REQUIRE(p != nullptr);
	ATF_REQUIRE_EQ(std::string(p), "tail10");
}

ATF_TEST_CASE_WITHOUT_HEAD(isLong_rejects_other_chars);
ATF_TEST_CASE_BODY(isLong_rejects_other_chars)
{
	ATF_REQUIRE_EQ(isLong("--foo_bar"), nullptr);
	ATF_REQUIRE_EQ(isLong("--foo.bar"), nullptr);
	ATF_REQUIRE_EQ(isLong("--foo bar"), nullptr);
}

ATF_TEST_CASE_WITHOUT_HEAD(isLong_empty_name);
ATF_TEST_CASE_BODY(isLong_empty_name)
{
	auto p = isLong("--");
	ATF_REQUIRE(p != nullptr);
	ATF_REQUIRE_EQ(std::string(p), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(isCommand_known);
ATF_TEST_CASE_BODY(isCommand_known)
{
	ATF_REQUIRE_EQ(isCommand("create"),   CmdCreate);
	ATF_REQUIRE_EQ(isCommand("run"),      CmdRun);
	ATF_REQUIRE_EQ(isCommand("validate"), CmdValidate);
	ATF_REQUIRE_EQ(isCommand("snapshot"), CmdSnapshot);
	ATF_REQUIRE_EQ(isCommand("info"),     CmdInfo);
	ATF_REQUIRE_EQ(isCommand("clean"),    CmdClean);
	ATF_REQUIRE_EQ(isCommand("console"),  CmdConsole);
	ATF_REQUIRE_EQ(isCommand("export"),   CmdExport);
	ATF_REQUIRE_EQ(isCommand("import"),   CmdImport);
	ATF_REQUIRE_EQ(isCommand("gui"),      CmdGui);
	ATF_REQUIRE_EQ(isCommand("stack"),    CmdStack);
	ATF_REQUIRE_EQ(isCommand("stats"),    CmdStats);
	ATF_REQUIRE_EQ(isCommand("logs"),     CmdLogs);
	ATF_REQUIRE_EQ(isCommand("stop"),     CmdStop);
	ATF_REQUIRE_EQ(isCommand("restart"),  CmdRestart);
}

ATF_TEST_CASE_WITHOUT_HEAD(isCommand_list_aliases);
ATF_TEST_CASE_BODY(isCommand_list_aliases)
{
	ATF_REQUIRE_EQ(isCommand("list"), CmdList);
	ATF_REQUIRE_EQ(isCommand("ls"),   CmdList);
}

ATF_TEST_CASE_WITHOUT_HEAD(isCommand_unknown);
ATF_TEST_CASE_BODY(isCommand_unknown)
{
	ATF_REQUIRE_EQ(isCommand("delete"),    CmdNone);
	ATF_REQUIRE_EQ(isCommand("rm"),        CmdNone);
	ATF_REQUIRE_EQ(isCommand(""),          CmdNone);
	ATF_REQUIRE_EQ(isCommand("Create"),    CmdNone);
	ATF_REQUIRE_EQ(isCommand("create-xx"), CmdNone);
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, strEq_basic);
	ATF_ADD_TEST_CASE(tcs, strEq_case_sensitive);
	ATF_ADD_TEST_CASE(tcs, isShort_letters);
	ATF_ADD_TEST_CASE(tcs, isShort_digits);
	ATF_ADD_TEST_CASE(tcs, isShort_rejects_long);
	ATF_ADD_TEST_CASE(tcs, isShort_rejects_non_dash);
	ATF_ADD_TEST_CASE(tcs, isShort_rejects_punctuation);
	ATF_ADD_TEST_CASE(tcs, isShort_rejects_empty);
	ATF_ADD_TEST_CASE(tcs, isLong_basic);
	ATF_ADD_TEST_CASE(tcs, isLong_returns_nullptr_for_short);
	ATF_ADD_TEST_CASE(tcs, isLong_returns_nullptr_for_uppercase);
	ATF_ADD_TEST_CASE(tcs, isLong_accepts_dash);
	ATF_ADD_TEST_CASE(tcs, isLong_accepts_digits);
	ATF_ADD_TEST_CASE(tcs, isLong_rejects_other_chars);
	ATF_ADD_TEST_CASE(tcs, isLong_empty_name);
	ATF_ADD_TEST_CASE(tcs, isCommand_known);
	ATF_ADD_TEST_CASE(tcs, isCommand_list_aliases);
	ATF_ADD_TEST_CASE(tcs, isCommand_unknown);
}
