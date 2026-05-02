// ATF adversarial / boundary-condition tests for already-covered helpers.
//
// Where util_test/spec_test/etc. cover the happy path and a few obvious
// failure modes, this file pushes the helpers with:
//   - extreme sizes (empty, very long, max integer)
//   - boundary values (just above / just below limits)
//   - weird characters (null bytes, embedded escapes, unicode-ish)
//   - input that previous bugs would have exploited

#include <atf-c++.hpp>
#include <climits>
#include <cstdint>
#include <string>
#include <vector>

#include "util.h"
#include "stack_pure.h"
#include "spec_pure.h"
#include "lifecycle_pure.h"
#include "mib_pure.h"
#include "args_pure.h"
#include "err.h"

// ===================================================================
// Util::shellQuote — the security-critical bit
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_long_input);
ATF_TEST_CASE_BODY(shellQuote_long_input)
{
	// 100KB string with no special chars: should be wrapped in '...'.
	std::string big(100 * 1024, 'a');
	auto q = Util::shellQuote(big);
	ATF_REQUIRE_EQ(q.size(), big.size() + 2u);
	ATF_REQUIRE(q.front() == '\'');
	ATF_REQUIRE(q.back() == '\'');
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_many_quotes);
ATF_TEST_CASE_BODY(shellQuote_many_quotes)
{
	// 1000 single-quotes: must produce 1000 escapes.
	std::string s(1000, '\'');
	auto q = Util::shellQuote(s);
	// Expected: '<1000x \\''>' = 2 wrappers + 1000 * 4 chars = 4002
	ATF_REQUIRE_EQ(q.size(), 2u + 4u * 1000u);
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_null_byte);
ATF_TEST_CASE_BODY(shellQuote_null_byte)
{
	// std::string can hold embedded nulls — verify they survive.
	std::string s("a\0b", 3);
	auto q = Util::shellQuote(s);
	ATF_REQUIRE_EQ(q.size(), 5u);  // 'a\0b'
	ATF_REQUIRE_EQ(q[0], '\'');
	ATF_REQUIRE_EQ(q[2], '\0');
	ATF_REQUIRE_EQ(q[4], '\'');
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_high_bytes);
ATF_TEST_CASE_BODY(shellQuote_high_bytes)
{
	// Bytes 0x80..0xFF (UTF-8 continuation, etc.) pass through.
	std::string s;
	for (int b = 0x80; b < 0x100; b++) s.push_back((char)b);
	auto q = Util::shellQuote(s);
	ATF_REQUIRE_EQ(q.size(), 128u + 2u);
}

// ===================================================================
// Util::splitString — edge cases
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(splitString_only_delimiters);
ATF_TEST_CASE_BODY(splitString_only_delimiters)
{
	// "," — find loop yields all empty pieces, but the impl skips empties
	// when pos==0. Document the resulting size for ",,,".
	auto v = Util::splitString(",,,", ",");
	ATF_REQUIRE_EQ(v.size(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(splitString_long_input);
ATF_TEST_CASE_BODY(splitString_long_input)
{
	std::string big;
	for (int i = 0; i < 1000; i++) {
		if (i > 0) big += ",";
		big += "x";
	}
	auto v = Util::splitString(big, ",");
	ATF_REQUIRE_EQ(v.size(), 1000u);
}

ATF_TEST_CASE_WITHOUT_HEAD(splitString_delimiter_at_start);
ATF_TEST_CASE_BODY(splitString_delimiter_at_start)
{
	// ",a,b" — leading delimiter consumed; result {"a", "b"}.
	auto v = Util::splitString(",a,b", ",");
	ATF_REQUIRE_EQ(v.size(), 2u);
	ATF_REQUIRE_EQ(v[0], "a");
	ATF_REQUIRE_EQ(v[1], "b");
}

ATF_TEST_CASE_WITHOUT_HEAD(splitString_delimiter_at_end);
ATF_TEST_CASE_BODY(splitString_delimiter_at_end)
{
	auto v = Util::splitString("a,b,", ",");
	ATF_REQUIRE_EQ(v.size(), 2u);
	ATF_REQUIRE_EQ(v[0], "a");
	ATF_REQUIRE_EQ(v[1], "b");
}

// ===================================================================
// Util::Fs::hasExtension — case sensitivity, partial names
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(hasExtension_case_sensitive);
ATF_TEST_CASE_BODY(hasExtension_case_sensitive)
{
	ATF_REQUIRE(!Util::Fs::hasExtension("foo.YML", ".yml"));
	ATF_REQUIRE(Util::Fs::hasExtension("foo.YML", ".YML"));
}

ATF_TEST_CASE_WITHOUT_HEAD(hasExtension_dotfile);
ATF_TEST_CASE_BODY(hasExtension_dotfile)
{
	// ".hidden" — strrchr finds the leading dot, so ext = ".hidden".
	// Compared with ".hidden" → equal → returns true.
	ATF_REQUIRE(Util::Fs::hasExtension(".hidden", ".hidden"));
	// But ".hidden" does NOT match ".other" extension.
	ATF_REQUIRE(!Util::Fs::hasExtension(".hidden", ".other"));
}

ATF_TEST_CASE_WITHOUT_HEAD(hasExtension_no_dot);
ATF_TEST_CASE_BODY(hasExtension_no_dot)
{
	ATF_REQUIRE(!Util::Fs::hasExtension("README", ".md"));
	ATF_REQUIRE(!Util::Fs::hasExtension("", ".yml"));
}

// ===================================================================
// Util::isUrl — boundary
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(isUrl_minimum_valid);
ATF_TEST_CASE_BODY(isUrl_minimum_valid)
{
	// "http://x" = 8 chars. Code says size > 8 (strict >), so 8 chars rejected.
	ATF_REQUIRE(!Util::isUrl("http://x"));
	ATF_REQUIRE(Util::isUrl("http://xx"));     // 9 chars OK
	ATF_REQUIRE(!Util::isUrl("https://"));     // 8 chars rejected
	ATF_REQUIRE(Util::isUrl("https://x"));     // 9 chars OK
}

ATF_TEST_CASE_WITHOUT_HEAD(isUrl_uppercase_scheme);
ATF_TEST_CASE_BODY(isUrl_uppercase_scheme)
{
	// Current impl uses substr ==, so case-sensitive. RFC says scheme is
	// case-insensitive but pin down current behaviour.
	ATF_REQUIRE(!Util::isUrl("HTTP://example.com"));
	ATF_REQUIRE(!Util::isUrl("Http://example.com"));
}

// ===================================================================
// StackPure::parseCidr — prefix bounds and weird IPs
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_zero_prefix);
ATF_TEST_CASE_BODY(parseCidr_zero_prefix)
{
	uint32_t base; unsigned p;
	ATF_REQUIRE(StackPure::parseCidr("0.0.0.0/0", base, p));
	ATF_REQUIRE_EQ(p, 0u);
	ATF_REQUIRE_EQ(base, 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_oversize_prefix_rejected);
ATF_TEST_CASE_BODY(parseCidr_oversize_prefix_rejected)
{
	// Prefix > 32 is nonsensical for IPv4 — must be rejected.
	uint32_t base; unsigned p;
	ATF_REQUIRE(!StackPure::parseCidr("10.0.0.0/33", base, p));
	ATF_REQUIRE(!StackPure::parseCidr("10.0.0.0/64", base, p));
	ATF_REQUIRE(!StackPure::parseCidr("10.0.0.0/255", base, p));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_max_prefix_ok);
ATF_TEST_CASE_BODY(parseCidr_max_prefix_ok)
{
	// /32 is a valid IPv4 prefix (single host)
	uint32_t base; unsigned p;
	ATF_REQUIRE(StackPure::parseCidr("10.0.0.1/32", base, p));
	ATF_REQUIRE_EQ(p, 32u);
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_negative_prefix);
ATF_TEST_CASE_BODY(parseCidr_negative_prefix)
{
	uint32_t base; unsigned p;
	// "-1" parses through stoul as a wrapped value; std::stoul throws on
	// leading minus → parseCidr returns false. Pin down the behaviour.
	ATF_REQUIRE(!StackPure::parseCidr("10.0.0.0/-1", base, p));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_extra_text_after_prefix);
ATF_TEST_CASE_BODY(parseCidr_extra_text_after_prefix)
{
	uint32_t base; unsigned p;
	ATF_REQUIRE(!StackPure::parseCidr("10.0.0.0/24junk", base, p));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_empty_addr);
ATF_TEST_CASE_BODY(parseCidr_empty_addr)
{
	uint32_t base; unsigned p;
	ATF_REQUIRE(!StackPure::parseCidr("/24", base, p));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_empty_prefix);
ATF_TEST_CASE_BODY(parseCidr_empty_prefix)
{
	uint32_t base; unsigned p;
	ATF_REQUIRE(!StackPure::parseCidr("10.0.0.0/", base, p));
}

// ===================================================================
// SpecPure::parsePortRange — overflow / weirdness
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(parsePortRange_overflow_throws);
ATF_TEST_CASE_BODY(parsePortRange_overflow_throws)
{
	// 99999999999 > UINT_MAX → Util::toUInt throws.
	ATF_REQUIRE_THROW(Exception, SpecPure::parsePortRange("99999999999"));
	ATF_REQUIRE_THROW(Exception, SpecPure::parsePortRange("0-99999999999"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parsePortRange_negative_throws);
ATF_TEST_CASE_BODY(parsePortRange_negative_throws)
{
	// std::stoul rejects leading '-'.
	ATF_REQUIRE_THROW(Exception, SpecPure::parsePortRange("-1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parsePortRange_inverted_range);
ATF_TEST_CASE_BODY(parsePortRange_inverted_range)
{
	// parsePortRange does not validate that first <= second.
	auto r = SpecPure::parsePortRange("100-50");
	ATF_REQUIRE_EQ(r.first, 100u);
	ATF_REQUIRE_EQ(r.second, 50u);
}

// ===================================================================
// LifecyclePure::humanBytes — 64-bit boundaries
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(humanBytes_uint64_max);
ATF_TEST_CASE_BODY(humanBytes_uint64_max)
{
	auto out = LifecyclePure::humanBytes(UINT64_MAX);
	// UINT64_MAX bytes is ~16 EiB; expressed in G, that's a huge
	// number ending in 'G'. Don't pin the exact decimal — just the suffix.
	ATF_REQUIRE(out.back() == 'G');
}

ATF_TEST_CASE_WITHOUT_HEAD(humanBytes_one_byte_below_K);
ATF_TEST_CASE_BODY(humanBytes_one_byte_below_K)
{
	ATF_REQUIRE_EQ(LifecyclePure::humanBytes(1023), "1023B");
}

// ===================================================================
// MibPure::encodeOctetString — long strings
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(encodeOctetString_long);
ATF_TEST_CASE_BODY(encodeOctetString_long)
{
	std::string s(1023, 'x');
	std::vector<uint8_t> buf;
	MibPure::encodeOctetString(buf, s);
	// 4 (len header) + 1023 (string) + 1 (pad to 4-byte boundary) = 1028
	ATF_REQUIRE_EQ(buf.size(), 1028u);
	ATF_REQUIRE_EQ(buf.size() % 4u, 0u);
	// Header should be big-endian 1023 = 0x000003FF
	ATF_REQUIRE_EQ(buf[0], 0x00);
	ATF_REQUIRE_EQ(buf[1], 0x00);
	ATF_REQUIRE_EQ(buf[2], 0x03);
	ATF_REQUIRE_EQ(buf[3], 0xFF);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_minimal);
ATF_TEST_CASE_BODY(encodeOid_minimal)
{
	// Empty OID — pin down the behaviour.
	std::vector<uint8_t> buf;
	MibPure::encodeOid(buf, {});
	// 4-byte header (n_subid, prefix, include, reserved) + 0 sub-ids
	// per RFC 2741 §5.1.
	ATF_REQUIRE_EQ(buf.size(), 4u);
	ATF_REQUIRE_EQ(buf[0], 0x00);    // n_subid = 0
}

// ===================================================================
// StackPure::topoSort — stress + linear-chain length
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_long_chain);
ATF_TEST_CASE_BODY(topoSort_long_chain)
{
	// 100-node chain: a0 -> a1 -> ... -> a99, depend on the next.
	std::vector<StackPure::StackEntry> in;
	for (int i = 0; i < 100; i++) {
		StackPure::StackEntry e;
		e.name = "a" + std::to_string(i);
		if (i + 1 < 100) e.depends.push_back("a" + std::to_string(i + 1));
		in.push_back(e);
	}
	auto out = StackPure::topoSort(in);
	ATF_REQUIRE_EQ(out.size(), 100u);
	// First in sort order must be a99 (no deps), last must be a0.
	ATF_REQUIRE_EQ(out.front().name, "a99");
	ATF_REQUIRE_EQ(out.back().name, "a0");
}

ATF_TEST_CASE_WITHOUT_HEAD(topoSort_fan_out);
ATF_TEST_CASE_BODY(topoSort_fan_out)
{
	// One node depended on by many — the dependency must appear first.
	std::vector<StackPure::StackEntry> in;
	StackPure::StackEntry root; root.name = "root";
	in.push_back(root);
	for (int i = 0; i < 50; i++) {
		StackPure::StackEntry leaf;
		leaf.name = "leaf" + std::to_string(i);
		leaf.depends.push_back("root");
		in.push_back(leaf);
	}
	auto out = StackPure::topoSort(in);
	ATF_REQUIRE_EQ(out.size(), 51u);
	ATF_REQUIRE_EQ(out.front().name, "root");
}

// ===================================================================
// ArgsPure::isLong — additional adversarial cases beyond cli_args_test
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(isLong_triple_dash);
ATF_TEST_CASE_BODY(isLong_triple_dash)
{
	// "---help" — first two chars are "--", the rest is "-help".
	// '-' is allowed by current impl, so this should match as name "-help".
	auto p = ArgsPure::isLong("---help");
	ATF_REQUIRE(p != nullptr);
	ATF_REQUIRE_EQ(std::string(p), "-help");
}

ATF_TEST_CASE_WITHOUT_HEAD(isLong_just_two_dashes);
ATF_TEST_CASE_BODY(isLong_just_two_dashes)
{
	auto p = ArgsPure::isLong("--");
	ATF_REQUIRE(p != nullptr);
	ATF_REQUIRE_EQ(std::string(p), "");
}

ATF_INIT_TEST_CASES(tcs)
{
	// shellQuote
	ATF_ADD_TEST_CASE(tcs, shellQuote_long_input);
	ATF_ADD_TEST_CASE(tcs, shellQuote_many_quotes);
	ATF_ADD_TEST_CASE(tcs, shellQuote_null_byte);
	ATF_ADD_TEST_CASE(tcs, shellQuote_high_bytes);

	// splitString
	ATF_ADD_TEST_CASE(tcs, splitString_only_delimiters);
	ATF_ADD_TEST_CASE(tcs, splitString_long_input);
	ATF_ADD_TEST_CASE(tcs, splitString_delimiter_at_start);
	ATF_ADD_TEST_CASE(tcs, splitString_delimiter_at_end);

	// hasExtension
	ATF_ADD_TEST_CASE(tcs, hasExtension_case_sensitive);
	ATF_ADD_TEST_CASE(tcs, hasExtension_dotfile);
	ATF_ADD_TEST_CASE(tcs, hasExtension_no_dot);

	// isUrl
	ATF_ADD_TEST_CASE(tcs, isUrl_minimum_valid);
	ATF_ADD_TEST_CASE(tcs, isUrl_uppercase_scheme);

	// parseCidr
	ATF_ADD_TEST_CASE(tcs, parseCidr_zero_prefix);
	ATF_ADD_TEST_CASE(tcs, parseCidr_oversize_prefix_rejected);
	ATF_ADD_TEST_CASE(tcs, parseCidr_max_prefix_ok);
	ATF_ADD_TEST_CASE(tcs, parseCidr_negative_prefix);
	ATF_ADD_TEST_CASE(tcs, parseCidr_extra_text_after_prefix);
	ATF_ADD_TEST_CASE(tcs, parseCidr_empty_addr);
	ATF_ADD_TEST_CASE(tcs, parseCidr_empty_prefix);

	// parsePortRange
	ATF_ADD_TEST_CASE(tcs, parsePortRange_overflow_throws);
	ATF_ADD_TEST_CASE(tcs, parsePortRange_negative_throws);
	ATF_ADD_TEST_CASE(tcs, parsePortRange_inverted_range);

	// humanBytes
	ATF_ADD_TEST_CASE(tcs, humanBytes_uint64_max);
	ATF_ADD_TEST_CASE(tcs, humanBytes_one_byte_below_K);

	// MibPure
	ATF_ADD_TEST_CASE(tcs, encodeOctetString_long);
	ATF_ADD_TEST_CASE(tcs, encodeOid_minimal);

	// topoSort stress
	ATF_ADD_TEST_CASE(tcs, topoSort_long_chain);
	ATF_ADD_TEST_CASE(tcs, topoSort_fan_out);

	// isLong extra
	ATF_ADD_TEST_CASE(tcs, isLong_triple_dash);
	ATF_ADD_TEST_CASE(tcs, isLong_just_two_dashes);
}
