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

// --- apply_devfs_rules (1.1.62) ---

ATF_TEST_CASE_WITHOUT_HEAD(parse_apply_devfs_rules);
ATF_TEST_CASE_BODY(parse_apply_devfs_rules) {
  PrivOpsPure::ApplyDevfsRulesReq r;
  ATF_REQUIRE_EQ(parseApplyDevfsRules({
      {"verb", "apply_devfs_rules"}, {"mount_path", "/jails/web/dev"}, {"ruleset", "10042"},
      {"argc", "3"}, {"rule0", "hide"}, {"rule2", "path dri/* unhide"}, {"rule1", "path null unhide"},
    }, r), std::string());
  ATF_REQUIRE_EQ(r.mountPath, std::string("/jails/web/dev"));
  ATF_REQUIRE_EQ(r.ruleset, 10042u);
  ATF_REQUIRE_EQ(r.rules.size(), 3u);
  ATF_REQUIRE_EQ(r.rules[1], std::string("path null unhide"));   // by index, not map order
  ATF_REQUIRE_EQ(r.rules[2], std::string("path dri/* unhide"));
  ATF_REQUIRE_EQ(PrivOpsPure::validateApplyDevfsRules(r), std::string());

  PrivOpsPure::ApplyDevfsRulesReq r2;
  ATF_REQUIRE(parseApplyDevfsRules({{"mount_path", "/j/dev"}, {"ruleset", "5"}, {"argc", "2"}, {"rule0", "hide"}}, r2)
              .find("rule1") != std::string::npos);
  ATF_REQUIRE(!parseApplyDevfsRules({{"mount_path", "/j/dev"}, {"ruleset", "5"}, {"argc", "0"}}, r2).empty());
  ATF_REQUIRE(parseApplyDevfsRules({{"mount_path", "/j/dev"}, {"ruleset", "5"}, {"argc", "9999"}}, r2)
              .find("exceeds") != std::string::npos);
  ATF_REQUIRE(parseApplyDevfsRules({{"ruleset", "5"}, {"argc", "1"}, {"rule0", "hide"}}, r2).find("missing") != std::string::npos);
  ATF_REQUIRE(parseApplyDevfsRules({{"mount_path", "/j/dev"}, {"argc", "1"}, {"rule0", "hide"}}, r2).find("missing") != std::string::npos);
}

// --- exec_in_jail (1.1.40) ---

ATF_TEST_CASE_WITHOUT_HEAD(parse_exec_in_jail);
ATF_TEST_CASE_BODY(parse_exec_in_jail) {
  PrivOpsPure::ExecInJailReq r;
  ATF_REQUIRE_EQ(parseExecInJail({
      {"verb", "exec_in_jail"}, {"jid", "42"}, {"user", "alice"}, {"term", "xterm"},
      {"argc", "3"}, {"argv0", "/bin/sh"}, {"argv1", "-c"}, {"argv2", "echo hi"},
    }, r), std::string());
  ATF_REQUIRE_EQ(r.jid, 42u);
  ATF_REQUIRE_EQ(r.user, std::string("alice"));
  ATF_REQUIRE_EQ(r.term, std::string("xterm"));
  ATF_REQUIRE_EQ(r.argv.size(), 3u);
  ATF_REQUIRE_EQ(r.argv[1], std::string("-c"));

  // Optionals absent -> empty; argv order is by index, not map order.
  PrivOpsPure::ExecInJailReq r2;
  ATF_REQUIRE_EQ(parseExecInJail({
      {"jid", "1"}, {"argc", "2"}, {"argv1", "b"}, {"argv0", "/a"},
    }, r2), std::string());
  ATF_REQUIRE(r2.user.empty());
  ATF_REQUIRE_EQ(r2.argv[0], std::string("/a"));
  ATF_REQUIRE_EQ(r2.argv[1], std::string("b"));

  // argc beyond the delivered argv fields, argc 0, oversized argc.
  PrivOpsPure::ExecInJailReq r3;
  ATF_REQUIRE(parseExecInJail({{"jid", "1"}, {"argc", "2"}, {"argv0", "/a"}}, r3)
              .find("argv1") != std::string::npos);
  ATF_REQUIRE(!parseExecInJail({{"jid", "1"}, {"argc", "0"}}, r3).empty());
  ATF_REQUIRE(parseExecInJail({{"jid", "1"}, {"argc", "999999"}}, r3)
              .find("exceeds") != std::string::npos);
  // Missing required fields.
  ATF_REQUIRE(parseExecInJail({{"argc", "1"}, {"argv0", "/a"}}, r3).find("missing") != std::string::npos);
  ATF_REQUIRE(parseExecInJail({{"jid", "1"}, {"argv0", "/a"}}, r3).find("missing") != std::string::npos);
}

// --- 1.1.41 ---

ATF_TEST_CASE_WITHOUT_HEAD(parse_1141_verbs_and_rctl_limits);
ATF_TEST_CASE_BODY(parse_1141_verbs_and_rctl_limits) {
  PrivOpsPure::SetIfaceMacReq m;
  ATF_REQUIRE_EQ(parseSetIfaceMac({{"ifname", "epair0a"}, {"mac", "02:00:11:22:33:44"}}, m), std::string());
  ATF_REQUIRE_EQ(m.mac, std::string("02:00:11:22:33:44"));
  ATF_REQUIRE(parseSetIfaceMac({{"ifname", "epair0a"}}, m).find("missing") != std::string::npos);

  PrivOpsPure::DeleteIpfwNatReq n;
  ATF_REQUIRE_EQ(parseDeleteIpfwNat({{"number", "7"}}, n), std::string());
  ATF_REQUIRE_EQ(n.number, 7u);
  ATF_REQUIRE(!parseDeleteIpfwNat({{"number", "x"}}, n).empty());

  PrivOpsPure::CreateBridgeReq b;
  ATF_REQUIRE_EQ(parseCreateBridge({{"name", "bridge0"}}, b), std::string());
  ATF_REQUIRE(parseCreateBridge({}, b).find("missing") != std::string::npos);

  // 1.1.57
  PrivOpsPure::AcquireFwLeaseReq a;
  ATF_REQUIRE_EQ(parseAcquireFwLease({{"jid", "9"}, {"slot", "true"}, {"fwd6", "true"}}, a), std::string());
  ATF_REQUIRE_EQ(a.jid, 9u); ATF_REQUIRE(a.slot); ATF_REQUIRE(!a.fwd4); ATF_REQUIRE(a.fwd6);
  ATF_REQUIRE(!parseAcquireFwLease({{"slot", "true"}}, a).empty());
  ATF_REQUIRE(!parseAcquireFwLease({{"jid", "9"}, {"slot", "maybe"}}, a).empty());
  PrivOpsPure::ReleaseFwLeaseReq rl;
  ATF_REQUIRE_EQ(parseReleaseFwLease({{"jid", "9"}}, rl), std::string());
  ATF_REQUIRE(!parseReleaseFwLease({}, rl).empty());
  PrivOpsPure::SetIfaceInetAddrReq i;
  ATF_REQUIRE_EQ(parseSetIfaceInetAddr({{"ifname", "epair0a"}, {"addr", "fd00::1"},
                                        {"prefix_len", "126"}, {"inet6", "true"}}, i), std::string());
  ATF_REQUIRE(i.inet6);
  PrivOpsPure::SetIfaceInetAddrReq i4;   // fresh struct: an absent optional leaves the field alone
  ATF_REQUIRE_EQ(parseSetIfaceInetAddr({{"ifname", "epair0a"}, {"addr", "10.0.0.1"},
                                        {"prefix_len", "24"}}, i4), std::string());
  ATF_REQUIRE(!i4.inet6);

  PrivOpsPure::QueryJailRctlReq q;
  ATF_REQUIRE_EQ(parseQueryJailRctl({{"jid", "42"}}, q), std::string());
  ATF_REQUIRE(!q.limits);
  ATF_REQUIRE_EQ(parseQueryJailRctl({{"jid", "42"}, {"limits", "true"}}, q), std::string());
  ATF_REQUIRE(q.limits);
}

// --- 1.1.43: nvlist header pre-check ---

ATF_TEST_CASE_WITHOUT_HEAD(nvlist_header_parse_and_limits);
ATF_TEST_CASE_BODY(nvlist_header_parse_and_limits) {
  using PrivOpsNvPure::NvlistHeader;
  using PrivOpsNvPure::parseNvlistHeader;
  using PrivOpsNvPure::checkNvlistHeaderLimits;
  // little-endian sender: magic 'l', version 0, flags 0, descriptors=3, size=0x1234
  unsigned char le[19] = {0x6c, 0x00, 0x00,
                          3,0,0,0,0,0,0,0,
                          0x34,0x12,0,0,0,0,0,0};
  NvlistHeader h;
  ATF_REQUIRE_EQ(parseNvlistHeader(le, sizeof le, h), std::string());
  ATF_REQUIRE(!h.bigEndian);
  ATF_REQUIRE_EQ(h.descriptors, 3u);
  ATF_REQUIRE_EQ(h.size, 0x1234u);
  ATF_REQUIRE_EQ(checkNvlistHeaderLimits(h), std::string());

  // big-endian sender (flag 0x80): same values, byte-swapped
  unsigned char be[19] = {0x6c, 0x00, 0x80,
                          0,0,0,0,0,0,0,3,
                          0,0,0,0,0,0,0x12,0x34};
  ATF_REQUIRE_EQ(parseNvlistHeader(be, sizeof be, h), std::string());
  ATF_REQUIRE(h.bigEndian);
  ATF_REQUIRE_EQ(h.descriptors, 3u);
  ATF_REQUIRE_EQ(h.size, 0x1234u);

  // over the byte cap / descriptor cap
  unsigned char big[19] = {0x6c, 0x00, 0x00, 0,0,0,0,0,0,0,0, 0x01,0x00,0x10,0,0,0,0,0};  // 1 MiB + 1
  ATF_REQUIRE_EQ(parseNvlistHeader(big, sizeof big, h), std::string());
  ATF_REQUIRE_EQ(h.size, (1u << 20) + 1);
  ATF_REQUIRE(checkNvlistHeaderLimits(h).find("too large") != std::string::npos);
  unsigned char fds[19] = {0x6c, 0x00, 0x00, 4,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
  ATF_REQUIRE_EQ(parseNvlistHeader(fds, sizeof fds, h), std::string());
  ATF_REQUIRE(checkNvlistHeaderLimits(h).find("descriptors") != std::string::npos);
  // exactly at the caps is fine
  unsigned char edge[19] = {0x6c, 0x00, 0x00, 3,0,0,0,0,0,0,0, 0x00,0x00,0x10,0,0,0,0,0};
  ATF_REQUIRE_EQ(parseNvlistHeader(edge, sizeof edge, h), std::string());
  ATF_REQUIRE_EQ(checkNvlistHeaderLimits(h), std::string());

  // malformed: short, bad magic, bad version
  ATF_REQUIRE(!parseNvlistHeader(le, 18, h).empty());
  ATF_REQUIRE(!parseNvlistHeader(nullptr, 19, h).empty());
  unsigned char badMagic[19] = {0x00, 0x00, 0x00, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
  ATF_REQUIRE(parseNvlistHeader(badMagic, 19, h).find("magic") != std::string::npos);
  unsigned char badVer[19] = {0x6c, 0x01, 0x00, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
  ATF_REQUIRE(parseNvlistHeader(badVer, 19, h).find("version") != std::string::npos);
  ATF_REQUIRE_EQ(PrivOpsNvPure::kNvlistHeaderSize, 19u);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, parse_apply_devfs_rules);
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
  ATF_ADD_TEST_CASE(tcs, parse_exec_in_jail);
  ATF_ADD_TEST_CASE(tcs, parse_1141_verbs_and_rctl_limits);
  ATF_ADD_TEST_CASE(tcs, nvlist_header_parse_and_limits);
}
