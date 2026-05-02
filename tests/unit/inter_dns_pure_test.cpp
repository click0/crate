// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "inter_dns_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using InterDnsPure::Entry;
using InterDnsPure::validateHostname;
using InterDnsPure::normalizeName;
using InterDnsPure::buildUnboundFragment;
using InterDnsPure::buildHostsBlock;
using InterDnsPure::replaceHostsBlock;

// --- validateHostname ---

ATF_TEST_CASE_WITHOUT_HEAD(hostname_empty_rejected);
ATF_TEST_CASE_BODY(hostname_empty_rejected) {
  ATF_REQUIRE(!validateHostname("").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(hostname_too_long_rejected);
ATF_TEST_CASE_BODY(hostname_too_long_rejected) {
  ATF_REQUIRE_EQ(validateHostname(std::string(63, 'a')), std::string());
  ATF_REQUIRE(!validateHostname(std::string(64, 'a')).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(hostname_must_start_with_alnum);
ATF_TEST_CASE_BODY(hostname_must_start_with_alnum) {
  ATF_REQUIRE(!validateHostname("-foo").empty());
  ATF_REQUIRE(!validateHostname(".foo").empty());
  ATF_REQUIRE(!validateHostname("_foo").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(hostname_must_end_with_alnum);
ATF_TEST_CASE_BODY(hostname_must_end_with_alnum) {
  ATF_REQUIRE(!validateHostname("foo-").empty());
  ATF_REQUIRE(!validateHostname("foo.").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(hostname_no_underscores_or_dots);
ATF_TEST_CASE_BODY(hostname_no_underscores_or_dots) {
  // RFC 1123: only letters, digits, and hyphens in the body.
  ATF_REQUIRE(!validateHostname("foo_bar").empty());
  ATF_REQUIRE(!validateHostname("foo.bar").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(hostname_typical_names_accepted);
ATF_TEST_CASE_BODY(hostname_typical_names_accepted) {
  ATF_REQUIRE_EQ(validateHostname("a"),                  std::string());
  ATF_REQUIRE_EQ(validateHostname("alpha"),              std::string());
  ATF_REQUIRE_EQ(validateHostname("alpha-1"),            std::string());
  ATF_REQUIRE_EQ(validateHostname("a1b2"),               std::string());
  ATF_REQUIRE_EQ(validateHostname("MyJail-Prod-2026"),   std::string());
}

// --- normalizeName ---

ATF_TEST_CASE_WITHOUT_HEAD(normalize_lowercases);
ATF_TEST_CASE_BODY(normalize_lowercases) {
  ATF_REQUIRE_EQ(normalizeName("Alpha"),     std::string("alpha"));
  ATF_REQUIRE_EQ(normalizeName("MIXED-Case"), std::string("mixed-case"));
  ATF_REQUIRE_EQ(normalizeName("digits-1"),  std::string("digits-1"));
  ATF_REQUIRE_EQ(normalizeName(""),          std::string(""));
}

// --- buildUnboundFragment ---

ATF_TEST_CASE_WITHOUT_HEAD(unbound_empty_emits_zone_and_no_data);
ATF_TEST_CASE_BODY(unbound_empty_emits_zone_and_no_data) {
  auto out = buildUnboundFragment({});
  ATF_REQUIRE(out.find("local-zone: \"crate.\" static") != std::string::npos);
  ATF_REQUIRE(out.find("local-data:") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(unbound_emits_a_record);
ATF_TEST_CASE_BODY(unbound_emits_a_record) {
  std::vector<Entry> e = {{"alpha", "10.0.0.1", ""}};
  auto out = buildUnboundFragment(e);
  ATF_REQUIRE(out.find("local-data: \"alpha.crate. IN A 10.0.0.1\"") != std::string::npos);
  ATF_REQUIRE(out.find("AAAA") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(unbound_emits_aaaa_record_when_only_v6);
ATF_TEST_CASE_BODY(unbound_emits_aaaa_record_when_only_v6) {
  std::vector<Entry> e = {{"alpha", "", "fd00::1"}};
  auto out = buildUnboundFragment(e);
  ATF_REQUIRE(out.find("IN A ") == std::string::npos);
  ATF_REQUIRE(out.find("local-data: \"alpha.crate. IN AAAA fd00::1\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(unbound_dual_stack_emits_both);
ATF_TEST_CASE_BODY(unbound_dual_stack_emits_both) {
  std::vector<Entry> e = {{"alpha", "10.0.0.1", "fd00::1"}};
  auto out = buildUnboundFragment(e);
  ATF_REQUIRE(out.find("IN A 10.0.0.1") != std::string::npos);
  ATF_REQUIRE(out.find("IN AAAA fd00::1") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(unbound_sorts_entries_by_name);
ATF_TEST_CASE_BODY(unbound_sorts_entries_by_name) {
  std::vector<Entry> e = {
    {"zebra", "10.0.0.3", ""},
    {"alpha", "10.0.0.1", ""},
    {"middle","10.0.0.2", ""},
  };
  auto out = buildUnboundFragment(e);
  auto a = out.find("alpha.crate.");
  auto m = out.find("middle.crate.");
  auto z = out.find("zebra.crate.");
  ATF_REQUIRE(a != std::string::npos);
  ATF_REQUIRE(m != std::string::npos);
  ATF_REQUIRE(z != std::string::npos);
  ATF_REQUIRE(a < m);
  ATF_REQUIRE(m < z);
}

ATF_TEST_CASE_WITHOUT_HEAD(unbound_lowercases_names);
ATF_TEST_CASE_BODY(unbound_lowercases_names) {
  std::vector<Entry> e = {{"AlphaJail", "10.0.0.1", ""}};
  auto out = buildUnboundFragment(e);
  ATF_REQUIRE(out.find("alphajail.crate.") != std::string::npos);
  ATF_REQUIRE(out.find("AlphaJail")        == std::string::npos);
}

// --- buildHostsBlock ---

ATF_TEST_CASE_WITHOUT_HEAD(hosts_block_has_markers);
ATF_TEST_CASE_BODY(hosts_block_has_markers) {
  auto out = buildHostsBlock({});
  ATF_REQUIRE(out.find("# >>> crate inter-container DNS <<<") != std::string::npos);
  ATF_REQUIRE(out.find("# <<< crate inter-container DNS >>>") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(hosts_block_renders_v4_first);
ATF_TEST_CASE_BODY(hosts_block_renders_v4_first) {
  std::vector<Entry> e = {{"alpha", "10.0.0.1", "fd00::1"}};
  auto out = buildHostsBlock(e);
  ATF_REQUIRE(out.find("10.0.0.1\talpha.crate alpha") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(hosts_block_uses_v6_when_no_v4);
ATF_TEST_CASE_BODY(hosts_block_uses_v6_when_no_v4) {
  std::vector<Entry> e = {{"alpha", "", "fd00::1"}};
  auto out = buildHostsBlock(e);
  ATF_REQUIRE(out.find("fd00::1\talpha.crate alpha") != std::string::npos);
}

// --- replaceHostsBlock ---

ATF_TEST_CASE_WITHOUT_HEAD(replace_appends_when_missing);
ATF_TEST_CASE_BODY(replace_appends_when_missing) {
  std::string existing = "127.0.0.1\tlocalhost\n";
  std::string block    = "# >>> crate inter-container DNS <<<\n10.0.0.1\talpha\n# <<< crate inter-container DNS >>>\n";
  auto out = replaceHostsBlock(existing, block);
  ATF_REQUIRE(out.find("127.0.0.1\tlocalhost") != std::string::npos);
  ATF_REQUIRE(out.find("10.0.0.1\talpha")      != std::string::npos);
  // Existing line preserved.
  ATF_REQUIRE(out.rfind("127.0.0.1\tlocalhost", 0) == 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(replace_preserves_surrounding_lines);
ATF_TEST_CASE_BODY(replace_preserves_surrounding_lines) {
  std::string existing =
    "127.0.0.1\tlocalhost\n"
    "# >>> crate inter-container DNS <<<\n"
    "10.0.0.5\told\n"
    "# <<< crate inter-container DNS >>>\n"
    "192.168.1.10\tnas\n";
  std::string block =
    "# >>> crate inter-container DNS <<<\n"
    "10.0.0.1\tnew\n"
    "# <<< crate inter-container DNS >>>\n";
  auto out = replaceHostsBlock(existing, block);
  ATF_REQUIRE(out.find("localhost")    != std::string::npos);
  ATF_REQUIRE(out.find("nas")          != std::string::npos);
  ATF_REQUIRE(out.find("10.0.0.1\tnew")    != std::string::npos);
  ATF_REQUIRE(out.find("10.0.0.5\told")    == std::string::npos); // old block gone
}

ATF_TEST_CASE_WITHOUT_HEAD(replace_recovers_from_truncated_block);
ATF_TEST_CASE_BODY(replace_recovers_from_truncated_block) {
  // Operator killed crate mid-rebuild — there's a BEGIN marker but no END.
  std::string existing =
    "127.0.0.1\tlocalhost\n"
    "# >>> crate inter-container DNS <<<\n"
    "10.0.0.99\thalfwritten\n";
  std::string block =
    "# >>> crate inter-container DNS <<<\n"
    "10.0.0.1\tnew\n"
    "# <<< crate inter-container DNS >>>\n";
  auto out = replaceHostsBlock(existing, block);
  ATF_REQUIRE(out.find("localhost")           != std::string::npos);
  ATF_REQUIRE(out.find("halfwritten")         == std::string::npos);
  ATF_REQUIRE(out.find("10.0.0.1\tnew")           != std::string::npos);
  ATF_REQUIRE(out.find("# <<< crate inter-container DNS >>>") != std::string::npos);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, hostname_empty_rejected);
  ATF_ADD_TEST_CASE(tcs, hostname_too_long_rejected);
  ATF_ADD_TEST_CASE(tcs, hostname_must_start_with_alnum);
  ATF_ADD_TEST_CASE(tcs, hostname_must_end_with_alnum);
  ATF_ADD_TEST_CASE(tcs, hostname_no_underscores_or_dots);
  ATF_ADD_TEST_CASE(tcs, hostname_typical_names_accepted);
  ATF_ADD_TEST_CASE(tcs, normalize_lowercases);
  ATF_ADD_TEST_CASE(tcs, unbound_empty_emits_zone_and_no_data);
  ATF_ADD_TEST_CASE(tcs, unbound_emits_a_record);
  ATF_ADD_TEST_CASE(tcs, unbound_emits_aaaa_record_when_only_v6);
  ATF_ADD_TEST_CASE(tcs, unbound_dual_stack_emits_both);
  ATF_ADD_TEST_CASE(tcs, unbound_sorts_entries_by_name);
  ATF_ADD_TEST_CASE(tcs, unbound_lowercases_names);
  ATF_ADD_TEST_CASE(tcs, hosts_block_has_markers);
  ATF_ADD_TEST_CASE(tcs, hosts_block_renders_v4_first);
  ATF_ADD_TEST_CASE(tcs, hosts_block_uses_v6_when_no_v4);
  ATF_ADD_TEST_CASE(tcs, replace_appends_when_missing);
  ATF_ADD_TEST_CASE(tcs, replace_preserves_surrounding_lines);
  ATF_ADD_TEST_CASE(tcs, replace_recovers_from_truncated_block);
}
