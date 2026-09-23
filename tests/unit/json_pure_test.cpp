// ATF unit tests for JsonPure (lib/json_pure.cpp).
//
// The single JSON string escaper every JSON-emitting module delegates to
// (1.1.29). A bug here produces invalid or injectable JSON everywhere at
// once: `crate list/inspect/doctor --json`, the audit log, the daemon's
// control-socket and HTTP responses, and the hub.

#include <atf-c++.hpp>
#include <string>

#include "json_pure.h"

using JsonPure::escape;
using JsonPure::quote;

ATF_TEST_CASE_WITHOUT_HEAD(plain_text_unchanged);
ATF_TEST_CASE_BODY(plain_text_unchanged)
{
	ATF_REQUIRE_EQ(escape(""), "");
	ATF_REQUIRE_EQ(escape("web-01.example"), "web-01.example");
	ATF_REQUIRE_EQ(escape("a b/c:d"), "a b/c:d");   // '/' needs no escape
}

ATF_TEST_CASE_WITHOUT_HEAD(quote_and_backslash);
ATF_TEST_CASE_BODY(quote_and_backslash)
{
	ATF_REQUIRE_EQ(escape("a\"b"), "a\\\"b");
	ATF_REQUIRE_EQ(escape("a\\b"), "a\\\\b");
	// The classic key-injection attempt stays inside the string.
	ATF_REQUIRE_EQ(escape("x\",\"evil\":\"y"), "x\\\",\\\"evil\\\":\\\"y");
}

ATF_TEST_CASE_WITHOUT_HEAD(short_form_controls);
ATF_TEST_CASE_BODY(short_form_controls)
{
	ATF_REQUIRE_EQ(escape("\b"), "\\b");
	ATF_REQUIRE_EQ(escape("\f"), "\\f");
	ATF_REQUIRE_EQ(escape("\n"), "\\n");
	ATF_REQUIRE_EQ(escape("\r"), "\\r");
	ATF_REQUIRE_EQ(escape("\t"), "\\t");
}

ATF_TEST_CASE_WITHOUT_HEAD(other_controls_are_u00xx);
ATF_TEST_CASE_BODY(other_controls_are_u00xx)
{
	// Four hex digits, zero-padded, lowercase — the width bug that made
	// hub/scheduling_pure emit `\u1` (1.1.27) must be impossible here.
	ATF_REQUIRE_EQ(escape(std::string(1, '\0')), "\\u0000");
	ATF_REQUIRE_EQ(escape("\x01"), "\\u0001");
	ATF_REQUIRE_EQ(escape("\x1b[31m"), "\\u001b[31m");   // ANSI colour (ESC)
	ATF_REQUIRE_EQ(escape("\x1f"), "\\u001f");
	// Every byte 0x00..0x1f produces valid output of the expected shape.
	for (int c = 0; c < 0x20; c++) {
		auto e = escape(std::string(1, static_cast<char>(c)));
		ATF_REQUIRE(e.size() == 2 || e.size() == 6);
		ATF_REQUIRE_EQ(e[0], '\\');
	}
}

ATF_TEST_CASE_WITHOUT_HEAD(high_bytes_pass_through);
ATF_TEST_CASE_BODY(high_bytes_pass_through)
{
	// UTF-8 is legal inside a JSON string. A signed-char comparison
	// (`c < 0x20` on a negative char) used to "escape" these (1.1.27).
	ATF_REQUIRE_EQ(escape("\xd0\x9a\xd0\xb8\xd1\x97\xd0\xb2"),
	               "\xd0\x9a\xd0\xb8\xd1\x97\xd0\xb2");   // "Київ"
	ATF_REQUIRE_EQ(escape("\x7f"), "\x7f");               // DEL is legal
	ATF_REQUIRE_EQ(escape("\xff"), "\xff");
}

ATF_TEST_CASE_WITHOUT_HEAD(quote_wraps);
ATF_TEST_CASE_BODY(quote_wraps)
{
	ATF_REQUIRE_EQ(quote(""), "\"\"");
	ATF_REQUIRE_EQ(quote("a\nb"), "\"a\\nb\"");
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, plain_text_unchanged);
	ATF_ADD_TEST_CASE(tcs, quote_and_backslash);
	ATF_ADD_TEST_CASE(tcs, short_form_controls);
	ATF_ADD_TEST_CASE(tcs, other_controls_are_u00xx);
	ATF_ADD_TEST_CASE(tcs, high_bytes_pass_through);
	ATF_ADD_TEST_CASE(tcs, quote_wraps);
}
