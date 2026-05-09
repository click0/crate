// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_wire_pure.h"

#include <atf-c++.hpp>

#include <string>

using namespace PrivOpsWirePure;
using PrivOpsPure::Verb;

// --- Generic extractors ---

ATF_TEST_CASE_WITHOUT_HEAD(extract_string_present_absent_wrong_type);
ATF_TEST_CASE_BODY(extract_string_present_absent_wrong_type) {
  std::string out;
  // Present
  ATF_REQUIRE_EQ(extractStringField(R"({"name":"foo"})", "name", out),
                 std::string(kPresent));
  ATF_REQUIRE_EQ(out, std::string("foo"));
  // Absent -> empty
  ATF_REQUIRE_EQ(extractStringField(R"({"x":"y"})", "name", out),
                 std::string(""));
  // Wrong type (number)
  std::string err = extractStringField(R"({"name":42})", "name", out);
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err != kPresent);
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_string_decodes_escapes);
ATF_TEST_CASE_BODY(extract_string_decodes_escapes) {
  std::string out;
  ATF_REQUIRE_EQ(extractStringField(R"({"name":"a\"b\\c"})", "name", out),
                 std::string(kPresent));
  ATF_REQUIRE_EQ(out, std::string("a\"b\\c"));
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_string_unterminated);
ATF_TEST_CASE_BODY(extract_string_unterminated) {
  std::string out;
  std::string err = extractStringField(R"({"name":"foo)", "name", out);
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err != kPresent);
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_long_present_absent_wrong);
ATF_TEST_CASE_BODY(extract_long_present_absent_wrong) {
  long v = 0;
  ATF_REQUIRE_EQ(extractLongField(R"({"jid":42})", "jid", v),
                 std::string(kPresent));
  ATF_REQUIRE_EQ(v, 42);

  ATF_REQUIRE_EQ(extractLongField(R"({"x":1})", "jid", v),
                 std::string(""));

  std::string err = extractLongField(R"({"jid":"foo"})", "jid", v);
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err != kPresent);

  // Negative integers ok
  ATF_REQUIRE_EQ(extractLongField(R"({"jid":-1})", "jid", v),
                 std::string(kPresent));
  ATF_REQUIRE_EQ(v, -1);

  // Floats rejected
  err = extractLongField(R"({"jid":1.5})", "jid", v);
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err != kPresent);
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_unsigned_rejects_negative);
ATF_TEST_CASE_BODY(extract_unsigned_rejects_negative) {
  unsigned v = 0;
  ATF_REQUIRE_EQ(extractUnsignedField(R"({"set":5})", "set", v),
                 std::string(kPresent));
  ATF_REQUIRE_EQ(v, 5u);

  std::string err = extractUnsignedField(R"({"set":-1})", "set", v);
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err != kPresent);
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_bool);
ATF_TEST_CASE_BODY(extract_bool) {
  bool v = false;
  ATF_REQUIRE_EQ(extractBoolField(R"({"vnet":true})", "vnet", v),
                 std::string(kPresent));
  ATF_REQUIRE(v);

  v = true;
  ATF_REQUIRE_EQ(extractBoolField(R"({"vnet":false})", "vnet", v),
                 std::string(kPresent));
  ATF_REQUIRE(!v);

  std::string err = extractBoolField(R"({"vnet":"yes"})", "vnet", v);
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err != kPresent);
}

ATF_TEST_CASE_WITHOUT_HEAD(require_field_reports_missing);
ATF_TEST_CASE_BODY(require_field_reports_missing) {
  std::string s;
  std::string err = requireStringField(R"({})", "name", s);
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err.find("missing") != std::string::npos);
  ATF_REQUIRE(err.find("name") != std::string::npos);

  long v = 0;
  err = requireLongField(R"({})", "jid", v);
  ATF_REQUIRE(err.find("missing") != std::string::npos);
}

// --- parseVerbFromPath ---

ATF_TEST_CASE_WITHOUT_HEAD(verb_path_known);
ATF_TEST_CASE_BODY(verb_path_known) {
  ATF_REQUIRE(parseVerbFromPath("/api/v1/privops/create_jail") == Verb::CreateJail);
  ATF_REQUIRE(parseVerbFromPath("/api/v1/privops/set_rctl") == Verb::SetRctl);
  ATF_REQUIRE(parseVerbFromPath("/api/v1/privops/add_pf_rule") == Verb::AddPfRule);
}

ATF_TEST_CASE_WITHOUT_HEAD(verb_path_rejects_garbage);
ATF_TEST_CASE_BODY(verb_path_rejects_garbage) {
  ATF_REQUIRE(parseVerbFromPath("") == Verb::Unknown);
  ATF_REQUIRE(parseVerbFromPath("/api/v1/privops/") == Verb::Unknown);
  ATF_REQUIRE(parseVerbFromPath("/api/v1/privops/create_jail/") == Verb::Unknown);
  ATF_REQUIRE(parseVerbFromPath("/api/v1/privops/create_jail/extra") == Verb::Unknown);
  ATF_REQUIRE(parseVerbFromPath("/api/v1/privops/unknown_verb") == Verb::Unknown);
  ATF_REQUIRE(parseVerbFromPath("/api/v1/containers/foo") == Verb::Unknown);
}

// --- Per-verb parsers ---

ATF_TEST_CASE_WITHOUT_HEAD(parse_create_jail_minimal);
ATF_TEST_CASE_BODY(parse_create_jail_minimal) {
  PrivOpsPure::CreateJailReq r;
  ATF_REQUIRE_EQ(parseCreateJail(
      R"({"name":"alpine","path":"/zroot/jails/alpine"})", r),
      std::string());
  ATF_REQUIRE_EQ(r.name, std::string("alpine"));
  ATF_REQUIRE_EQ(r.path, std::string("/zroot/jails/alpine"));
  ATF_REQUIRE_EQ(r.hostname, std::string());
  ATF_REQUIRE(!r.vnet);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_create_jail_full);
ATF_TEST_CASE_BODY(parse_create_jail_full) {
  PrivOpsPure::CreateJailReq r;
  ATF_REQUIRE_EQ(parseCreateJail(
      R"({"name":"a","path":"/p","hostname":"h.local","vnet":true,"parameters":"allow.raw_sockets=1"})",
      r),
      std::string());
  ATF_REQUIRE_EQ(r.hostname, std::string("h.local"));
  ATF_REQUIRE(r.vnet);
  ATF_REQUIRE_EQ(r.parameters, std::string("allow.raw_sockets=1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_create_jail_missing_required);
ATF_TEST_CASE_BODY(parse_create_jail_missing_required) {
  PrivOpsPure::CreateJailReq r;
  std::string err = parseCreateJail(R"({"path":"/p"})", r);
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err.find("name") != std::string::npos);

  err = parseCreateJail(R"({"name":"a"})", r);
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err.find("path") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_destroy_jail);
ATF_TEST_CASE_BODY(parse_destroy_jail) {
  PrivOpsPure::DestroyJailReq r;
  ATF_REQUIRE_EQ(parseDestroyJail(R"({"name":"foo","force":true})", r), std::string());
  ATF_REQUIRE_EQ(r.name, std::string("foo"));
  ATF_REQUIRE(r.force);
  // force defaults to false
  PrivOpsPure::DestroyJailReq r2;
  ATF_REQUIRE_EQ(parseDestroyJail(R"({"name":"foo"})", r2), std::string());
  ATF_REQUIRE(!r2.force);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_mount_nullfs);
ATF_TEST_CASE_BODY(parse_mount_nullfs) {
  PrivOpsPure::MountNullfsReq r;
  ATF_REQUIRE_EQ(parseMountNullfs(
      R"({"source":"/host","target":"/jail/host","read_only":false})", r),
      std::string());
  ATF_REQUIRE_EQ(r.source, std::string("/host"));
  ATF_REQUIRE_EQ(r.target, std::string("/jail/host"));
  ATF_REQUIRE(!r.readOnly);

  // read_only defaults to true
  PrivOpsPure::MountNullfsReq r2;
  ATF_REQUIRE_EQ(parseMountNullfs(
      R"({"source":"/h","target":"/j"})", r2),
      std::string());
  ATF_REQUIRE(r2.readOnly);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_set_rctl);
ATF_TEST_CASE_BODY(parse_set_rctl) {
  PrivOpsPure::SetRctlReq r;
  ATF_REQUIRE_EQ(parseSetRctl(
      R"({"jid":7,"key":"pcpu","value":"20"})", r),
      std::string());
  ATF_REQUIRE_EQ(r.jid, 7);
  ATF_REQUIRE_EQ(r.key, std::string("pcpu"));
  ATF_REQUIRE_EQ(r.rawValue, std::string("20"));

  // Missing jid -> error
  std::string err = parseSetRctl(R"({"key":"pcpu","value":"20"})", r);
  ATF_REQUIRE(err.find("jid") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_attach_zfs);
ATF_TEST_CASE_BODY(parse_attach_zfs) {
  PrivOpsPure::AttachZfsReq r;
  ATF_REQUIRE_EQ(parseAttachZfs(
      R"({"jid":3,"dataset":"zroot/jails/alpine"})", r),
      std::string());
  ATF_REQUIRE_EQ(r.jid, 3);
  ATF_REQUIRE_EQ(r.dataset, std::string("zroot/jails/alpine"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_configure_iface_optional_fields);
ATF_TEST_CASE_BODY(parse_configure_iface_optional_fields) {
  PrivOpsPure::ConfigureIfaceReq r;
  ATF_REQUIRE_EQ(parseConfigureIface(
      R"({"jid":5,"ifname":"epair0b","bridge":"bridge0","ipv4_cidr":"10.0.0.5/24"})",
      r),
      std::string());
  ATF_REQUIRE_EQ(r.jid, 5);
  ATF_REQUIRE_EQ(r.ifname, std::string("epair0b"));
  ATF_REQUIRE_EQ(r.bridge, std::string("bridge0"));
  ATF_REQUIRE_EQ(r.ipv4Cidr, std::string("10.0.0.5/24"));
  ATF_REQUIRE_EQ(r.ipv6Cidr, std::string());
  ATF_REQUIRE_EQ(r.macAddr, std::string());

  // Both v4 + v6 + mac populated
  PrivOpsPure::ConfigureIfaceReq r2;
  ATF_REQUIRE_EQ(parseConfigureIface(
      R"({"jid":5,"ifname":"e","ipv6_cidr":"fd00::5/64","mac_addr":"02:00:11:22:33:44"})",
      r2),
      std::string());
  ATF_REQUIRE_EQ(r2.ipv6Cidr, std::string("fd00::5/64"));
  ATF_REQUIRE_EQ(r2.macAddr, std::string("02:00:11:22:33:44"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_add_pf_rule);
ATF_TEST_CASE_BODY(parse_add_pf_rule) {
  PrivOpsPure::AddPfRuleReq r;
  ATF_REQUIRE_EQ(parseAddPfRule(
      R"({"anchor":"crate","rule":"pass on em0 from 10.0.0.0/24"})", r),
      std::string());
  ATF_REQUIRE_EQ(r.anchor, std::string("crate"));
  ATF_REQUIRE_EQ(r.ruleText, std::string("pass on em0 from 10.0.0.0/24"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_add_ipfw_rule);
ATF_TEST_CASE_BODY(parse_add_ipfw_rule) {
  PrivOpsPure::AddIpfwRuleReq r;
  ATF_REQUIRE_EQ(parseAddIpfwRule(
      R"({"set":0,"number":100,"action":"allow","body":"ip from any to any"})", r),
      std::string());
  ATF_REQUIRE_EQ(r.set, 0u);
  ATF_REQUIRE_EQ(r.number, 100u);
  ATF_REQUIRE_EQ(r.action, std::string("allow"));
  ATF_REQUIRE_EQ(r.body, std::string("ip from any to any"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_remove_ipfw_rule_minimal);
ATF_TEST_CASE_BODY(parse_remove_ipfw_rule_minimal) {
  PrivOpsPure::RemoveIpfwRuleReq r;
  ATF_REQUIRE_EQ(parseRemoveIpfwRule(R"({"set":0,"number":100})", r),
                 std::string());
  ATF_REQUIRE_EQ(r.set, 0u);
  ATF_REQUIRE_EQ(r.number, 100u);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_clear_rctl);
ATF_TEST_CASE_BODY(parse_clear_rctl) {
  PrivOpsPure::ClearRctlReq r;
  ATF_REQUIRE_EQ(parseClearRctl(R"({"jid":7,"key":"pcpu"})", r), std::string());
  ATF_REQUIRE_EQ(r.jid, 7);
  ATF_REQUIRE_EQ(r.key, std::string("pcpu"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_detach_zfs);
ATF_TEST_CASE_BODY(parse_detach_zfs) {
  PrivOpsPure::DetachZfsReq r;
  ATF_REQUIRE_EQ(parseDetachZfs(
      R"({"jid":3,"dataset":"zroot/jails/foo"})", r),
      std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_unmount_nullfs);
ATF_TEST_CASE_BODY(parse_unmount_nullfs) {
  PrivOpsPure::UnmountNullfsReq r;
  ATF_REQUIRE_EQ(parseUnmountNullfs(R"({"target":"/jail/host","force":true})", r),
                 std::string());
  ATF_REQUIRE(r.force);
  ATF_REQUIRE_EQ(r.target, std::string("/jail/host"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_teardown_iface);
ATF_TEST_CASE_BODY(parse_teardown_iface) {
  PrivOpsPure::TeardownIfaceReq r;
  ATF_REQUIRE_EQ(parseTeardownIface(R"({"ifname":"epair0a"})", r),
                 std::string());
  ATF_REQUIRE_EQ(r.ifname, std::string("epair0a"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_remove_pf_rule);
ATF_TEST_CASE_BODY(parse_remove_pf_rule) {
  PrivOpsPure::RemovePfRuleReq r;
  ATF_REQUIRE_EQ(parseRemovePfRule(
      R"({"anchor":"crate","rule":"pass quick"})", r),
      std::string());
}

// --- Response body builders ---

ATF_TEST_CASE_WITHOUT_HEAD(format_not_implemented_includes_verb);
ATF_TEST_CASE_BODY(format_not_implemented_includes_verb) {
  std::string body = formatNotImplemented(Verb::CreateJail);
  ATF_REQUIRE(body.find("create_jail") != std::string::npos);
  ATF_REQUIRE(body.find("\"error\"") != std::string::npos);
  ATF_REQUIRE(body.find("not yet implemented") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_parse_error_escapes_quotes);
ATF_TEST_CASE_BODY(format_parse_error_escapes_quotes) {
  std::string body = formatParseError("missing field 'name'");
  ATF_REQUIRE(body.find("\"error\"") != std::string::npos);
  ATF_REQUIRE(body.find("parse:") != std::string::npos);
  // No double-quote leak inside the body
  ATF_REQUIRE(body.find("name'") != std::string::npos);

  // Quote in the reason gets escaped
  std::string b2 = formatParseError(R"(say "hi")");
  ATF_REQUIRE(b2.find(R"(\")") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_validate_error_distinct_prefix);
ATF_TEST_CASE_BODY(format_validate_error_distinct_prefix) {
  std::string body = formatValidateError("path must be absolute");
  ATF_REQUIRE(body.find("validate:") != std::string::npos);
  ATF_REQUIRE(body.find("parse:") == std::string::npos);
}

// --- Per-verb success/error builders (0.9.2) ---

ATF_TEST_CASE_WITHOUT_HEAD(format_handler_error_includes_kind);
ATF_TEST_CASE_BODY(format_handler_error_includes_kind) {
  std::string body = formatHandlerError("exec_failed", "rctl(8) exited 1");
  ATF_REQUIRE(body.find("exec_failed") != std::string::npos);
  ATF_REQUIRE(body.find("rctl(8) exited 1") != std::string::npos);
  ATF_REQUIRE(body.find("\"error\"") != std::string::npos);

  // Newlines / tabs in the reason get escaped, not raw-emitted.
  std::string b2 = formatHandlerError("k", "line1\nline2");
  ATF_REQUIRE(b2.find("\\n") != std::string::npos);
  ATF_REQUIRE(b2.find("\nline2") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_set_rctl_success);
ATF_TEST_CASE_BODY(format_set_rctl_success) {
  std::string body = formatSetRctlSuccess(7, "pcpu", "20");
  ATF_REQUIRE(body.find("\"set\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"jid\":7") != std::string::npos);
  ATF_REQUIRE(body.find("\"key\":\"pcpu\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"value\":\"20\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_set_rctl_escapes_value);
ATF_TEST_CASE_BODY(format_set_rctl_escapes_value) {
  // Value won't realistically contain a backslash post-validate,
  // but defence in depth catches a future regression.
  std::string body = formatSetRctlSuccess(1, "pcpu", "20\\bad");
  // Escaped: 20\\bad
  ATF_REQUIRE(body.find("20\\\\bad") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_clear_rctl_success);
ATF_TEST_CASE_BODY(format_clear_rctl_success) {
  std::string body = formatClearRctlSuccess(7, "pcpu");
  ATF_REQUIRE(body.find("\"cleared\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"jid\":7") != std::string::npos);
  ATF_REQUIRE(body.find("\"key\":\"pcpu\"") != std::string::npos);
  // Distinct from set: no "value" / "set" fields.
  ATF_REQUIRE(body.find("\"set\":") == std::string::npos);
  ATF_REQUIRE(body.find("\"value\":") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_attach_zfs_success);
ATF_TEST_CASE_BODY(format_attach_zfs_success) {
  std::string body = formatAttachZfsSuccess(3, "zroot/jails/alpine/data");
  ATF_REQUIRE(body.find("\"attached\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"jid\":3") != std::string::npos);
  ATF_REQUIRE(body.find("\"dataset\":\"zroot/jails/alpine/data\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"detached\":") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_detach_zfs_success);
ATF_TEST_CASE_BODY(format_detach_zfs_success) {
  std::string body = formatDetachZfsSuccess(3, "zroot/jails/alpine/data");
  ATF_REQUIRE(body.find("\"detached\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"jid\":3") != std::string::npos);
  ATF_REQUIRE(body.find("\"dataset\":\"zroot/jails/alpine/data\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"attached\":") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_mount_nullfs_success_ro);
ATF_TEST_CASE_BODY(format_mount_nullfs_success_ro) {
  std::string body = formatMountNullfsSuccess("/host/data", "/jail/data", true);
  ATF_REQUIRE(body.find("\"mounted\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"source\":\"/host/data\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"target\":\"/jail/data\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"read_only\":true") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_mount_nullfs_success_rw);
ATF_TEST_CASE_BODY(format_mount_nullfs_success_rw) {
  std::string body = formatMountNullfsSuccess("/host", "/jail", false);
  ATF_REQUIRE(body.find("\"read_only\":false") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_unmount_nullfs_success);
ATF_TEST_CASE_BODY(format_unmount_nullfs_success) {
  std::string body = formatUnmountNullfsSuccess("/jail/data");
  ATF_REQUIRE(body.find("\"unmounted\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"target\":\"/jail/data\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"mounted\":") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_configure_iface_success);
ATF_TEST_CASE_BODY(format_configure_iface_success) {
  std::string body = formatConfigureIfaceSuccess(
      5, "epair0b", "bridge0", "10.0.0.5/24", "fd00::5/64",
      "02:00:11:22:33:44");
  ATF_REQUIRE(body.find("\"configured\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"jid\":5") != std::string::npos);
  ATF_REQUIRE(body.find("\"ifname\":\"epair0b\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"bridge\":\"bridge0\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"ipv4_cidr\":\"10.0.0.5/24\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"ipv6_cidr\":\"fd00::5/64\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"mac_addr\":\"02:00:11:22:33:44\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_configure_iface_empty_optional);
ATF_TEST_CASE_BODY(format_configure_iface_empty_optional) {
  // Empty optional fields are echoed as empty strings (not omitted)
  // so operator scripts can grep for them deterministically.
  std::string body = formatConfigureIfaceSuccess(
      5, "epair0b", "", "10.0.0.5/24", "", "");
  ATF_REQUIRE(body.find("\"bridge\":\"\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"ipv6_cidr\":\"\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"mac_addr\":\"\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_teardown_iface_success);
ATF_TEST_CASE_BODY(format_teardown_iface_success) {
  std::string body = formatTeardownIfaceSuccess("epair0a");
  ATF_REQUIRE(body.find("\"destroyed\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"ifname\":\"epair0a\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"configured\":") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_add_pf_rule_success);
ATF_TEST_CASE_BODY(format_add_pf_rule_success) {
  std::string body = formatAddPfRuleSuccess("crate", "pass on em0");
  ATF_REQUIRE(body.find("\"loaded\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"anchor\":\"crate\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"rule\":\"pass on em0\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_remove_pf_rule_success);
ATF_TEST_CASE_BODY(format_remove_pf_rule_success) {
  std::string body = formatRemovePfRuleSuccess("crate");
  ATF_REQUIRE(body.find("\"flushed_anchor\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"anchor\":\"crate\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"loaded\":") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_add_ipfw_rule_success);
ATF_TEST_CASE_BODY(format_add_ipfw_rule_success) {
  std::string body = formatAddIpfwRuleSuccess(0, 100, "allow",
                                              "ip from any to any");
  ATF_REQUIRE(body.find("\"added\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"set\":0") != std::string::npos);
  ATF_REQUIRE(body.find("\"number\":100") != std::string::npos);
  ATF_REQUIRE(body.find("\"action\":\"allow\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"body\":\"ip from any to any\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_remove_ipfw_rule_success);
ATF_TEST_CASE_BODY(format_remove_ipfw_rule_success) {
  std::string body = formatRemoveIpfwRuleSuccess(0, 100);
  ATF_REQUIRE(body.find("\"removed\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"number\":100") != std::string::npos);
  ATF_REQUIRE(body.find("\"added\":") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_create_jail_success);
ATF_TEST_CASE_BODY(format_create_jail_success) {
  std::string body = formatCreateJailSuccess("alpine", "/zroot/jails/alpine");
  ATF_REQUIRE(body.find("\"created\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"name\":\"alpine\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"path\":\"/zroot/jails/alpine\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_destroy_jail_success);
ATF_TEST_CASE_BODY(format_destroy_jail_success) {
  std::string body = formatDestroyJailSuccess("alpine");
  ATF_REQUIRE(body.find("\"destroyed\":true") != std::string::npos);
  ATF_REQUIRE(body.find("\"name\":\"alpine\"") != std::string::npos);
  ATF_REQUIRE(body.find("\"created\":") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_create_epair_response_extracts);
ATF_TEST_CASE_BODY(format_create_epair_response_extracts) {
  // 0.9.26: first response-data verb. Lock down that the body
  // shape `{"created":true,"a":"epair0a","b":"epair0b"}` is
  // re-extractable via extractStringField (the path the client
  // in run_net.cpp uses).
  std::string body = formatCreateEpairSuccess("epair17a", "epair17b");
  ATF_REQUIRE(body.find("\"created\":true") != std::string::npos);
  std::string a, b;
  ATF_REQUIRE_EQ(extractStringField(body, "a", a), std::string(kPresent));
  ATF_REQUIRE_EQ(a, std::string("epair17a"));
  ATF_REQUIRE_EQ(extractStringField(body, "b", b), std::string(kPresent));
  ATF_REQUIRE_EQ(b, std::string("epair17b"));
}

// --- parseValidateAndDispatch ---

ATF_TEST_CASE_WITHOUT_HEAD(dispatch_unknown_returns_404);
ATF_TEST_CASE_BODY(dispatch_unknown_returns_404) {
  auto r = parseValidateAndDispatch(Verb::Unknown, "{}");
  ATF_REQUIRE_EQ(r.status, 404);
  ATF_REQUIRE(r.body.find("unknown") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(dispatch_parse_error_returns_400);
ATF_TEST_CASE_BODY(dispatch_parse_error_returns_400) {
  // Missing required `name` field
  auto r = parseValidateAndDispatch(Verb::CreateJail, R"({"path":"/p"})");
  ATF_REQUIRE_EQ(r.status, 400);
  ATF_REQUIRE(r.body.find("parse:") != std::string::npos);
  ATF_REQUIRE(r.body.find("name") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(dispatch_validate_error_returns_400);
ATF_TEST_CASE_BODY(dispatch_validate_error_returns_400) {
  // Parses fine but path has `..` segment -> validate rejects
  auto r = parseValidateAndDispatch(Verb::CreateJail,
      R"({"name":"alpine","path":"/zroot/../etc"})");
  ATF_REQUIRE_EQ(r.status, 400);
  ATF_REQUIRE(r.body.find("validate:") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(dispatch_happy_returns_501);
ATF_TEST_CASE_BODY(dispatch_happy_returns_501) {
  auto r = parseValidateAndDispatch(Verb::CreateJail,
      R"({"name":"alpine","path":"/zroot/jails/alpine"})");
  ATF_REQUIRE_EQ(r.status, 501);
  ATF_REQUIRE(r.body.find("create_jail") != std::string::npos);
  ATF_REQUIRE(r.body.find("not yet implemented") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(dispatch_covers_every_verb);
ATF_TEST_CASE_BODY(dispatch_covers_every_verb) {
  // For every verb, the dispatcher must reach a parse step (not
  // 404). We use empty body so most verbs hit "missing field"
  // (HTTP 400 parse:), confirming the switch handles every case.
  PrivOpsPure::Verb verbs[] = {
    Verb::CreateJail, Verb::DestroyJail,
    Verb::MountNullfs, Verb::UnmountNullfs,
    Verb::SetRctl, Verb::ClearRctl,
    Verb::AttachZfs, Verb::DetachZfs,
    Verb::ConfigureIface, Verb::TeardownIface,
    Verb::AddPfRule, Verb::RemovePfRule,
    Verb::AddIpfwRule, Verb::RemoveIpfwRule,
  };
  for (auto v : verbs) {
    auto r = parseValidateAndDispatch(v, "{}");
    // 400 for any required-field-bearing verb. None of them
    // should slip through to 404.
    ATF_REQUIRE(r.status == 400 || r.status == 501);
  }
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, extract_string_present_absent_wrong_type);
  ATF_ADD_TEST_CASE(tcs, extract_string_decodes_escapes);
  ATF_ADD_TEST_CASE(tcs, extract_string_unterminated);
  ATF_ADD_TEST_CASE(tcs, extract_long_present_absent_wrong);
  ATF_ADD_TEST_CASE(tcs, extract_unsigned_rejects_negative);
  ATF_ADD_TEST_CASE(tcs, extract_bool);
  ATF_ADD_TEST_CASE(tcs, require_field_reports_missing);

  ATF_ADD_TEST_CASE(tcs, verb_path_known);
  ATF_ADD_TEST_CASE(tcs, verb_path_rejects_garbage);

  ATF_ADD_TEST_CASE(tcs, parse_create_jail_minimal);
  ATF_ADD_TEST_CASE(tcs, parse_create_jail_full);
  ATF_ADD_TEST_CASE(tcs, parse_create_jail_missing_required);
  ATF_ADD_TEST_CASE(tcs, parse_destroy_jail);
  ATF_ADD_TEST_CASE(tcs, parse_mount_nullfs);
  ATF_ADD_TEST_CASE(tcs, parse_unmount_nullfs);
  ATF_ADD_TEST_CASE(tcs, parse_set_rctl);
  ATF_ADD_TEST_CASE(tcs, parse_clear_rctl);
  ATF_ADD_TEST_CASE(tcs, parse_attach_zfs);
  ATF_ADD_TEST_CASE(tcs, parse_detach_zfs);
  ATF_ADD_TEST_CASE(tcs, parse_configure_iface_optional_fields);
  ATF_ADD_TEST_CASE(tcs, parse_teardown_iface);
  ATF_ADD_TEST_CASE(tcs, parse_add_pf_rule);
  ATF_ADD_TEST_CASE(tcs, parse_remove_pf_rule);
  ATF_ADD_TEST_CASE(tcs, parse_add_ipfw_rule);
  ATF_ADD_TEST_CASE(tcs, parse_remove_ipfw_rule_minimal);

  ATF_ADD_TEST_CASE(tcs, format_not_implemented_includes_verb);
  ATF_ADD_TEST_CASE(tcs, format_parse_error_escapes_quotes);
  ATF_ADD_TEST_CASE(tcs, format_validate_error_distinct_prefix);
  ATF_ADD_TEST_CASE(tcs, format_handler_error_includes_kind);
  ATF_ADD_TEST_CASE(tcs, format_set_rctl_success);
  ATF_ADD_TEST_CASE(tcs, format_set_rctl_escapes_value);
  ATF_ADD_TEST_CASE(tcs, format_clear_rctl_success);
  ATF_ADD_TEST_CASE(tcs, format_attach_zfs_success);
  ATF_ADD_TEST_CASE(tcs, format_detach_zfs_success);
  ATF_ADD_TEST_CASE(tcs, format_mount_nullfs_success_ro);
  ATF_ADD_TEST_CASE(tcs, format_mount_nullfs_success_rw);
  ATF_ADD_TEST_CASE(tcs, format_unmount_nullfs_success);
  ATF_ADD_TEST_CASE(tcs, format_configure_iface_success);
  ATF_ADD_TEST_CASE(tcs, format_configure_iface_empty_optional);
  ATF_ADD_TEST_CASE(tcs, format_teardown_iface_success);
  ATF_ADD_TEST_CASE(tcs, format_add_pf_rule_success);
  ATF_ADD_TEST_CASE(tcs, format_remove_pf_rule_success);
  ATF_ADD_TEST_CASE(tcs, format_add_ipfw_rule_success);
  ATF_ADD_TEST_CASE(tcs, format_remove_ipfw_rule_success);
  ATF_ADD_TEST_CASE(tcs, format_create_jail_success);
  ATF_ADD_TEST_CASE(tcs, format_destroy_jail_success);
  ATF_ADD_TEST_CASE(tcs, format_create_epair_response_extracts);

  ATF_ADD_TEST_CASE(tcs, dispatch_unknown_returns_404);
  ATF_ADD_TEST_CASE(tcs, dispatch_parse_error_returns_400);
  ATF_ADD_TEST_CASE(tcs, dispatch_validate_error_returns_400);
  ATF_ADD_TEST_CASE(tcs, dispatch_happy_returns_501);
  ATF_ADD_TEST_CASE(tcs, dispatch_covers_every_verb);
}
