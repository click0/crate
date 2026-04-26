// ATF unit tests for pure helpers from cli/args.cpp.
//
// cli/args.cpp is a 1022-line file in a setuid-root binary, so it carries
// real risk: a bug in flag/command recognition silently breaks the entire
// CLI surface. parseArguments() and Args::validate() have side effects
// (exit(), file-existence checks) that make full coverage hard from a
// unit test, so we cover the pure helpers exhaustively here:
//
//   - strEq      — strcmp wrapper
//   - isShort    — single-letter short option detection ("-h", "-V")
//   - isLong     — long option detection ("--help") returning the name
//   - isCommand  — argv[1] -> Command enum
//
// Build:
//   c++ -std=c++17 -Ilib -o tests/unit/cli_args_test \
//       tests/unit/cli_args_test.cpp -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <cctype>
#include <cstring>

// ===================================================================
// Local copies of pure functions from cli/args.cpp, plus the minimum
// of the Command enum needed to exercise isCommand().
// ===================================================================

enum Command {
	CmdNone, CmdCreate, CmdRun, CmdValidate, CmdSnapshot, CmdExport,
	CmdImport, CmdGui, CmdList, CmdInfo, CmdClean, CmdConsole,
	CmdStack, CmdStats, CmdLogs, CmdStop, CmdRestart
};

static bool strEq(const char *s1, const char *s2) {
	return strcmp(s1, s2) == 0;
}

static char isShort(const char* arg) {
	if (arg[0] == '-' && (isalpha(arg[1]) || isdigit(arg[1])) && arg[2] == 0)
		return arg[1];
	return 0;
}

static const char* isLong(const char* arg) {
	if (arg[0] == '-' && arg[1] == '-') {
		for (int i = 2; arg[i]; i++)
			if (!islower(arg[i]) && !isdigit(arg[i]) && arg[i] != '-')
				return nullptr;
		return arg + 2;
	}
	return nullptr;
}

static Command isCommand(const char* arg) {
	if (strEq(arg, "create"))   return CmdCreate;
	if (strEq(arg, "run"))      return CmdRun;
	if (strEq(arg, "validate")) return CmdValidate;
	if (strEq(arg, "snapshot")) return CmdSnapshot;
	if (strEq(arg, "list") || strEq(arg, "ls")) return CmdList;
	if (strEq(arg, "info"))     return CmdInfo;
	if (strEq(arg, "clean"))    return CmdClean;
	if (strEq(arg, "console"))  return CmdConsole;
	if (strEq(arg, "export"))   return CmdExport;
	if (strEq(arg, "import"))   return CmdImport;
	if (strEq(arg, "gui"))      return CmdGui;
	if (strEq(arg, "stack"))    return CmdStack;
	if (strEq(arg, "stats"))    return CmdStats;
	if (strEq(arg, "logs"))     return CmdLogs;
	if (strEq(arg, "stop"))     return CmdStop;
	if (strEq(arg, "restart"))  return CmdRestart;
	return CmdNone;
}

// ===================================================================
// Tests: strEq
// ===================================================================

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

// ===================================================================
// Tests: isShort — must accept "-x" where x is alpha/digit, len==2
// ===================================================================

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
	// --help is not a short option
	ATF_REQUIRE_EQ(isShort("--help"), 0);
	// -hh is not a short option (too long)
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

// ===================================================================
// Tests: isLong — must accept "--name" and return the name
// ===================================================================

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
	// Current implementation requires lowercase only — uppercase rejected.
	// (See the islower(arg[i]) check at args.cpp:336.)
	ATF_REQUIRE_EQ(isLong("--Help"), nullptr);
	ATF_REQUIRE_EQ(isLong("--HELP"), nullptr);
}

ATF_TEST_CASE_WITHOUT_HEAD(isLong_accepts_dash);
ATF_TEST_CASE_BODY(isLong_accepts_dash)
{
	// Long options often contain a dash (--no-color, --log-progress).
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
	// Anything outside [a-z0-9-] is rejected.
	ATF_REQUIRE_EQ(isLong("--foo_bar"), nullptr);  // underscore
	ATF_REQUIRE_EQ(isLong("--foo.bar"), nullptr);  // dot
	ATF_REQUIRE_EQ(isLong("--foo bar"), nullptr);  // space
}

ATF_TEST_CASE_WITHOUT_HEAD(isLong_empty_name);
ATF_TEST_CASE_BODY(isLong_empty_name)
{
	// "--" alone — pointer to empty string
	auto p = isLong("--");
	ATF_REQUIRE(p != nullptr);
	ATF_REQUIRE_EQ(std::string(p), "");
}

// ===================================================================
// Tests: isCommand — every documented command + alias
// ===================================================================

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
	// Both "list" and "ls" map to CmdList
	ATF_REQUIRE_EQ(isCommand("list"), CmdList);
	ATF_REQUIRE_EQ(isCommand("ls"),   CmdList);
}

ATF_TEST_CASE_WITHOUT_HEAD(isCommand_unknown);
ATF_TEST_CASE_BODY(isCommand_unknown)
{
	ATF_REQUIRE_EQ(isCommand("delete"),    CmdNone);
	ATF_REQUIRE_EQ(isCommand("rm"),        CmdNone);
	ATF_REQUIRE_EQ(isCommand(""),          CmdNone);
	ATF_REQUIRE_EQ(isCommand("Create"),    CmdNone);  // case-sensitive
	ATF_REQUIRE_EQ(isCommand("create-xx"), CmdNone);
}

// ===================================================================
// Registration
// ===================================================================

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
