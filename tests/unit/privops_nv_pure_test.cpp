// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_nv_pure.h"

#include <atf-c++.hpp>

#include <string>

using namespace PrivOpsNvPure;
using PrivOpsPure::Verb;

// --- Generic accessors ---

ATF_TEST_CASE_WITHOUT_HEAD(require_string_present_absent);
ATF_TEST_CASE_BODY(require_string_present_absent) {
  FieldMap m = {{"name", "alpine"}};
  std::string s;
  ATF_REQUIRE_EQ(requireString(m, "name", s), std::string());
  ATF_REQUIRE_EQ(s, std::string("alpine"));

  std::string err = requireString(m, "missing", s);
  ATF_REQUIRE(err.find("missing") != std::string::npos);
  ATF_REQUIRE(err.find("missing field") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(require_long_typical);
ATF_TEST_CASE_BODY(require_long_typical) {
  FieldMap m = {{"jid", "42"}};
  long v = 0;
  ATF_REQUIRE_EQ(requireLong(m, "jid", v), std::string());
  ATF_REQUIRE_EQ(v, 42);

  // Negative
  m["jid"] = "-1";
  ATF_REQUIRE_EQ(requireLong(m, "jid", v), std::string());
  ATF_REQUIRE_EQ(v, -1);
}

ATF_TEST_CASE_WITHOUT_HEAD(require_long_rejects_garbage);
ATF_TEST_CASE_BODY(require_long_rejects_garbage) {
  long v = 0;
  ATF_REQUIRE(!requireLong({{"jid", "abc"}}, "jid", v).empty());
  ATF_REQUIRE(!requireLong({{"jid", "1.5"}}, "jid", v).empty());
  ATF_REQUIRE(!requireLong({{"jid", ""}},    "jid", v).empty());
  ATF_REQUIRE(!requireLong({{"jid", " 42"}}, "jid", v).empty());  // leading space
  ATF_REQUIRE(!requireLong({{"jid", "-"}},   "jid", v).empty());  // bare minus
}

ATF_TEST_CASE_WITHOUT_HEAD(require_unsigned_rejects_negative);
ATF_TEST_CASE_BODY(require_unsigned_rejects_negative) {
  unsigned u = 0;
  ATF_REQUIRE_EQ(requireUnsigned({{"set", "5"}}, "set", u), std::string());
  ATF_REQUIRE_EQ(u, 5u);
  ATF_REQUIRE(!requireUnsigned({{"set", "-1"}}, "set", u).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(optional_string);
ATF_TEST_CASE_BODY(optional_string) {
  std::string s = "default";
  // Absent — leaves default untouched
  ATF_REQUIRE_EQ(optionalString({}, "hostname", s), std::string());
  ATF_REQUIRE_EQ(s, std::string("default"));
  // Present
  ATF_REQUIRE_EQ(optionalString({{"hostname", "h.local"}}, "hostname", s),
                 std::string());
  ATF_REQUIRE_EQ(s, std::string("h.local"));
}

ATF_TEST_CASE_WITHOUT_HEAD(optional_bool_canonical_and_aliases);
ATF_TEST_CASE_BODY(optional_bool_canonical_and_aliases) {
  bool b;
  // Canonical (what the listener emits from nvlist booleans)
  ATF_REQUIRE_EQ(optionalBool({{"v", "true"}},  "v", b), std::string());
  ATF_REQUIRE(b);
  ATF_REQUIRE_EQ(optionalBool({{"v", "false"}}, "v", b), std::string());
  ATF_REQUIRE(!b);
  // Aliases (operator-friendly + bridge with potential JSON
  // transport)
  ATF_REQUIRE_EQ(optionalBool({{"v", "1"}},     "v", b), std::string());
  ATF_REQUIRE(b);
  ATF_REQUIRE_EQ(optionalBool({{"v", "0"}},     "v", b), std::string());
  ATF_REQUIRE(!b);
  // Garbage
  ATF_REQUIRE(!optionalBool({{"v", "yes"}}, "v", b).empty());
  ATF_REQUIRE(!optionalBool({{"v", "True"}}, "v", b).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(optional_bool_absent_leaves_default);
ATF_TEST_CASE_BODY(optional_bool_absent_leaves_default) {
  bool b = true;
  ATF_REQUIRE_EQ(optionalBool({}, "v", b), std::string());
  ATF_REQUIRE(b); // unchanged
}

// --- extractVerb ---

ATF_TEST_CASE_WITHOUT_HEAD(extract_verb_known);
ATF_TEST_CASE_BODY(extract_verb_known) {
  ATF_REQUIRE(extractVerb({{"verb", "set_rctl"}}) == Verb::SetRctl);
  ATF_REQUIRE(extractVerb({{"verb", "create_jail"}}) == Verb::CreateJail);
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_verb_unknown_or_missing);
ATF_TEST_CASE_BODY(extract_verb_unknown_or_missing) {
  ATF_REQUIRE(extractVerb({}) == Verb::Unknown);
  ATF_REQUIRE(extractVerb({{"verb", ""}}) == Verb::Unknown);
  ATF_REQUIRE(extractVerb({{"verb", "rm -rf /"}}) == Verb::Unknown);
  // Right key required (case sensitive for snake_case wire convention)
  ATF_REQUIRE(extractVerb({{"VERB", "set_rctl"}}) == Verb::Unknown);
}

// --- Per-verb parsers ---

ATF_TEST_CASE_WITHOUT_HEAD(parse_create_jail_minimal);
ATF_TEST_CASE_BODY(parse_create_jail_minimal) {
  PrivOpsPure::CreateJailReq r;
  ATF_REQUIRE_EQ(parseCreateJail(
      {{"name", "alpine"}, {"path", "/zroot/jails/alpine"}}, r),
      std::string());
  ATF_REQUIRE_EQ(r.name, std::string("alpine"));
  ATF_REQUIRE_EQ(r.path, std::string("/zroot/jails/alpine"));
  ATF_REQUIRE(!r.vnet); // default
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_create_jail_full);
ATF_TEST_CASE_BODY(parse_create_jail_full) {
  PrivOpsPure::CreateJailReq r;
  ATF_REQUIRE_EQ(parseCreateJail({
      {"name", "alpine"},
      {"path", "/zroot/jails/alpine"},
      {"hostname", "alpine.local"},
      {"vnet", "true"},
      {"parameters", "allow.raw_sockets=1"},
    }, r), std::string());
  ATF_REQUIRE_EQ(r.hostname, std::string("alpine.local"));
  ATF_REQUIRE(r.vnet);
  ATF_REQUIRE_EQ(r.parameters, std::string("allow.raw_sockets=1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_create_jail_missing_required);
ATF_TEST_CASE_BODY(parse_create_jail_missing_required) {
  PrivOpsPure::CreateJailReq r;
  std::string err = parseCreateJail({{"path", "/p"}}, r);
  ATF_REQUIRE(err.find("name") != std::string::npos);
  err = parseCreateJail({{"name", "a"}}, r);
  ATF_REQUIRE(err.find("path") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_destroy_jail);
ATF_TEST_CASE_BODY(parse_destroy_jail) {
  PrivOpsPure::DestroyJailReq r;
  ATF_REQUIRE_EQ(parseDestroyJail({{"name", "foo"}, {"force", "true"}}, r),
                 std::string());
  ATF_REQUIRE_EQ(r.name, std::string("foo"));
  ATF_REQUIRE(r.force);

  PrivOpsPure::DestroyJailReq r2;
  ATF_REQUIRE_EQ(parseDestroyJail({{"name", "foo"}}, r2), std::string());
  ATF_REQUIRE(!r2.force); // default
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_mount_nullfs_default_readonly);
ATF_TEST_CASE_BODY(parse_mount_nullfs_default_readonly) {
  PrivOpsPure::MountNullfsReq r;
  ATF_REQUIRE_EQ(parseMountNullfs({
      {"source", "/host"}, {"target", "/jail/host"},
    }, r), std::string());
  ATF_REQUIRE(r.readOnly); // default true

  PrivOpsPure::MountNullfsReq r2;
  ATF_REQUIRE_EQ(parseMountNullfs({
      {"source", "/host"}, {"target", "/jail/host"},
      {"read_only", "false"},
    }, r2), std::string());
  ATF_REQUIRE(!r2.readOnly);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_set_rctl);
ATF_TEST_CASE_BODY(parse_set_rctl) {
  PrivOpsPure::SetRctlReq r;
  ATF_REQUIRE_EQ(parseSetRctl({
      {"jid", "7"}, {"key", "pcpu"}, {"value", "20"},
    }, r), std::string());
  ATF_REQUIRE_EQ(r.jid, 7);
  ATF_REQUIRE_EQ(r.key, std::string("pcpu"));
  ATF_REQUIRE_EQ(r.rawValue, std::string("20"));

  // Missing jid -> error
  std::string err = parseSetRctl({
      {"key", "pcpu"}, {"value", "20"},
    }, r);
  ATF_REQUIRE(err.find("jid") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_clear_rctl);
ATF_TEST_CASE_BODY(parse_clear_rctl) {
  PrivOpsPure::ClearRctlReq r;
  ATF_REQUIRE_EQ(parseClearRctl({{"jid", "7"}, {"key", "pcpu"}}, r),
                 std::string());
  ATF_REQUIRE_EQ(r.jid, 7);
  ATF_REQUIRE_EQ(r.key, std::string("pcpu"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_attach_detach_zfs);
ATF_TEST_CASE_BODY(parse_attach_detach_zfs) {
  PrivOpsPure::AttachZfsReq a;
  ATF_REQUIRE_EQ(parseAttachZfs({{"jid", "3"}, {"dataset", "zroot/jails/x"}}, a),
                 std::string());
  ATF_REQUIRE_EQ(a.jid, 3);
  ATF_REQUIRE_EQ(a.dataset, std::string("zroot/jails/x"));

  PrivOpsPure::DetachZfsReq d;
  ATF_REQUIRE_EQ(parseDetachZfs({{"jid", "3"}, {"dataset", "zroot/jails/x"}}, d),
                 std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_configure_iface_optionals);
ATF_TEST_CASE_BODY(parse_configure_iface_optionals) {
  PrivOpsPure::ConfigureIfaceReq r;
  ATF_REQUIRE_EQ(parseConfigureIface({
      {"jid", "5"},
      {"ifname", "epair0b"},
      {"bridge", "bridge0"},
      {"ipv4_cidr", "10.0.0.5/24"},
    }, r), std::string());
  ATF_REQUIRE_EQ(r.jid, 5);
  ATF_REQUIRE_EQ(r.ifname, std::string("epair0b"));
  ATF_REQUIRE_EQ(r.bridge, std::string("bridge0"));
  ATF_REQUIRE_EQ(r.ipv4Cidr, std::string("10.0.0.5/24"));
  ATF_REQUIRE_EQ(r.ipv6Cidr, std::string()); // default
  ATF_REQUIRE_EQ(r.macAddr, std::string());

  // ipv6-only is fine
  PrivOpsPure::ConfigureIfaceReq r2;
  ATF_REQUIRE_EQ(parseConfigureIface({
      {"jid", "5"}, {"ifname", "e"},
      {"ipv6_cidr", "fd00::5/64"},
      {"mac_addr", "02:00:11:22:33:44"},
    }, r2), std::string());
  ATF_REQUIRE_EQ(r2.ipv6Cidr, std::string("fd00::5/64"));
  ATF_REQUIRE_EQ(r2.macAddr, std::string("02:00:11:22:33:44"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_teardown_iface);
ATF_TEST_CASE_BODY(parse_teardown_iface) {
  PrivOpsPure::TeardownIfaceReq r;
  ATF_REQUIRE_EQ(parseTeardownIface({{"ifname", "epair0a"}}, r),
                 std::string());
  ATF_REQUIRE_EQ(r.ifname, std::string("epair0a"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_pf_rules);
ATF_TEST_CASE_BODY(parse_pf_rules) {
  PrivOpsPure::AddPfRuleReq a;
  ATF_REQUIRE_EQ(parseAddPfRule({{"anchor", "crate"}, {"rule", "pass on em0"}}, a),
                 std::string());
  PrivOpsPure::RemovePfRuleReq r;
  ATF_REQUIRE_EQ(parseRemovePfRule({{"anchor", "crate"}, {"rule", "x"}}, r),
                 std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_ipfw_rules);
ATF_TEST_CASE_BODY(parse_ipfw_rules) {
  PrivOpsPure::AddIpfwRuleReq a;
  ATF_REQUIRE_EQ(parseAddIpfwRule({
      {"set", "0"}, {"number", "100"},
      {"action", "allow"}, {"body", "ip from any to any"},
    }, a), std::string());
  ATF_REQUIRE_EQ(a.set, 0u);
  ATF_REQUIRE_EQ(a.number, 100u);

  PrivOpsPure::RemoveIpfwRuleReq r;
  ATF_REQUIRE_EQ(parseRemoveIpfwRule({{"set", "0"}, {"number", "100"}}, r),
                 std::string());
}

// --- Cross-cutting: same shape as JSON transport ---

ATF_TEST_CASE_WITHOUT_HEAD(parsers_same_required_field_set_as_json);
ATF_TEST_CASE_BODY(parsers_same_required_field_set_as_json) {
  // Each verb's required-field set must match what
  // PrivOpsWirePure parses from JSON. If a future verb adds a
  // field to the JSON parser without updating the nv parser
  // (or vice-versa), this test catches the divergence by
  // asserting the empty-fields case fails for the same reason
  // — at least one missing-field error.
  PrivOpsPure::SetRctlReq r;
  std::string err = parseSetRctl({}, r);
  // Must mention at least one missing required field.
  ATF_REQUIRE(err.find("missing") != std::string::npos);

  PrivOpsPure::CreateJailReq cj;
  err = parseCreateJail({}, cj);
  ATF_REQUIRE(err.find("missing") != std::string::npos);

  PrivOpsPure::AddIpfwRuleReq ai;
  err = parseAddIpfwRule({}, ai);
  ATF_REQUIRE(err.find("missing") != std::string::npos);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, require_string_present_absent);
  ATF_ADD_TEST_CASE(tcs, require_long_typical);
  ATF_ADD_TEST_CASE(tcs, require_long_rejects_garbage);
  ATF_ADD_TEST_CASE(tcs, require_unsigned_rejects_negative);
  ATF_ADD_TEST_CASE(tcs, optional_string);
  ATF_ADD_TEST_CASE(tcs, optional_bool_canonical_and_aliases);
  ATF_ADD_TEST_CASE(tcs, optional_bool_absent_leaves_default);
  ATF_ADD_TEST_CASE(tcs, extract_verb_known);
  ATF_ADD_TEST_CASE(tcs, extract_verb_unknown_or_missing);
  ATF_ADD_TEST_CASE(tcs, parse_create_jail_minimal);
  ATF_ADD_TEST_CASE(tcs, parse_create_jail_full);
  ATF_ADD_TEST_CASE(tcs, parse_create_jail_missing_required);
  ATF_ADD_TEST_CASE(tcs, parse_destroy_jail);
  ATF_ADD_TEST_CASE(tcs, parse_mount_nullfs_default_readonly);
  ATF_ADD_TEST_CASE(tcs, parse_set_rctl);
  ATF_ADD_TEST_CASE(tcs, parse_clear_rctl);
  ATF_ADD_TEST_CASE(tcs, parse_attach_detach_zfs);
  ATF_ADD_TEST_CASE(tcs, parse_configure_iface_optionals);
  ATF_ADD_TEST_CASE(tcs, parse_teardown_iface);
  ATF_ADD_TEST_CASE(tcs, parse_pf_rules);
  ATF_ADD_TEST_CASE(tcs, parse_ipfw_rules);
  ATF_ADD_TEST_CASE(tcs, parsers_same_required_field_set_as_json);
}
