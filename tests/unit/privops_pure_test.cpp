// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_pure.h"

#include <atf-c++.hpp>

#include <string>

using namespace PrivOpsPure;

// --- Verb name <-> token round-trip ---

ATF_TEST_CASE_WITHOUT_HEAD(verb_token_roundtrips_for_every_verb);
ATF_TEST_CASE_BODY(verb_token_roundtrips_for_every_verb) {
  // Every Verb in the enum must have a name that parses back to itself.
  // If a future verb is added without updating both directions of the
  // mapping, this test catches it.
  Verb verbs[] = {
    Verb::CreateJail, Verb::DestroyJail,
    Verb::MountNullfs, Verb::UnmountNullfs,
    Verb::SetRctl, Verb::ClearRctl,
    Verb::AttachZfs, Verb::DetachZfs,
    Verb::ConfigureIface, Verb::TeardownIface,
    Verb::AddPfRule, Verb::RemovePfRule,
    Verb::AddIpfwRule, Verb::RemoveIpfwRule,
    Verb::SetIfaceUp, Verb::DisableIfaceOffload,
    Verb::BridgeAddMember, Verb::BridgeDelMember,
    Verb::SetIfaceInetAddr, Verb::CreateEpair,
    Verb::SetLoginclassRctl, Verb::ClearLoginclassRctl,
  };
  for (Verb v : verbs) {
    std::string token = verbName(v);
    ATF_REQUIRE(!token.empty());
    ATF_REQUIRE(token != "unknown");
    ATF_REQUIRE(parseVerb(token) == v);
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(verb_unknown_token_returns_unknown);
ATF_TEST_CASE_BODY(verb_unknown_token_returns_unknown) {
  ATF_REQUIRE(parseVerb("") == Verb::Unknown);
  ATF_REQUIRE(parseVerb("createjail") == Verb::Unknown);     // no underscore
  ATF_REQUIRE(parseVerb("CREATE_JAIL") == Verb::Unknown);    // case
  ATF_REQUIRE(parseVerb("create-jail") == Verb::Unknown);    // dash
  ATF_REQUIRE(parseVerb("rm -rf /") == Verb::Unknown);
}

ATF_TEST_CASE_WITHOUT_HEAD(verb_tokens_are_snake_case_lowercase);
ATF_TEST_CASE_BODY(verb_tokens_are_snake_case_lowercase) {
  // Wire convention is snake_case lowercase. Lock it down so a
  // typo'd uppercase or camelCase token doesn't sneak in.
  Verb verbs[] = {
    Verb::CreateJail, Verb::DestroyJail,
    Verb::MountNullfs, Verb::UnmountNullfs,
    Verb::SetRctl, Verb::AttachZfs,
    Verb::ConfigureIface, Verb::AddPfRule,
  };
  for (Verb v : verbs) {
    std::string t = verbName(v);
    for (char c : t) {
      bool ok = (c >= 'a' && c <= 'z') || c == '_';
      ATF_REQUIRE(ok);
    }
  }
}

// --- validateJailName ---

ATF_TEST_CASE_WITHOUT_HEAD(jailname_accepts_typical);
ATF_TEST_CASE_BODY(jailname_accepts_typical) {
  ATF_REQUIRE_EQ(validateJailName("foo"), std::string());
  ATF_REQUIRE_EQ(validateJailName("foo-bar"), std::string());
  ATF_REQUIRE_EQ(validateJailName("foo_bar"), std::string());
  ATF_REQUIRE_EQ(validateJailName("alpine.dev"), std::string());
  ATF_REQUIRE_EQ(validateJailName("a"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(jailname_rejects_empty_and_reserved);
ATF_TEST_CASE_BODY(jailname_rejects_empty_and_reserved) {
  ATF_REQUIRE(!validateJailName("").empty());
  ATF_REQUIRE(!validateJailName(".").empty());
  ATF_REQUIRE(!validateJailName("..").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(jailname_rejects_metas);
ATF_TEST_CASE_BODY(jailname_rejects_metas) {
  ATF_REQUIRE(!validateJailName("foo;rm").empty());
  ATF_REQUIRE(!validateJailName("foo bar").empty());
  ATF_REQUIRE(!validateJailName("foo/bar").empty());
  ATF_REQUIRE(!validateJailName("foo`x`").empty());
  ATF_REQUIRE(!validateJailName("foo$bar").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(jailname_rejects_too_long);
ATF_TEST_CASE_BODY(jailname_rejects_too_long) {
  // 1.1.3: limit raised from 64 to 200 to accommodate the
  // `_pid<getpid()>` suffix that lib/run.cpp appends at runtime.
  std::string s(200, 'a');
  ATF_REQUIRE_EQ(validateJailName(s), std::string());
  s.push_back('a');
  ATF_REQUIRE(!validateJailName(s).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(jailname_accepts_runtime_pid_suffix);
ATF_TEST_CASE_BODY(jailname_accepts_runtime_pid_suffix) {
  // Regression coverage for the 1.1.3 fix: lib/run.cpp builds
  // jailXname = `<spec-name>_pid<getpid()>`. With the old 64-char
  // ceiling, any spec name >55 chars triggered a 400 from the
  // daemon validator. Verify the canonical real-world shape now
  // passes.
  std::string specName(60, 'a');                 // realistic long-ish name
  std::string suffix = "_pid99999";              // 9 chars (max-ish pid)
  ATF_REQUIRE_EQ(validateJailName(specName + suffix), std::string());

  // Even larger: 150-char spec name + pid suffix still fits 200.
  std::string longSpec(150, 'b');
  ATF_REQUIRE_EQ(validateJailName(longSpec + suffix), std::string());
}

// --- validateHostname ---

ATF_TEST_CASE_WITHOUT_HEAD(hostname_empty_is_ok);
ATF_TEST_CASE_BODY(hostname_empty_is_ok) {
  ATF_REQUIRE_EQ(validateHostname(""), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(hostname_accepts_typical);
ATF_TEST_CASE_BODY(hostname_accepts_typical) {
  ATF_REQUIRE_EQ(validateHostname("alpine.local"), std::string());
  ATF_REQUIRE_EQ(validateHostname("dev-01.crate"), std::string());
  ATF_REQUIRE_EQ(validateHostname("h"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(hostname_rejects_label_edge_cases);
ATF_TEST_CASE_BODY(hostname_rejects_label_edge_cases) {
  ATF_REQUIRE(!validateHostname("-leadinghyphen").empty());
  ATF_REQUIRE(!validateHostname("trailinghyphen-").empty());
  ATF_REQUIRE(!validateHostname("foo..bar").empty());            // empty label
  ATF_REQUIRE(!validateHostname(".foo").empty());                 // empty leading label
  ATF_REQUIRE(!validateHostname("foo_bar").empty());              // underscore not allowed
  ATF_REQUIRE(!validateHostname("foo bar").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(hostname_rejects_long_label);
ATF_TEST_CASE_BODY(hostname_rejects_long_label) {
  std::string label(64, 'a'); // 1 over the 63 limit
  ATF_REQUIRE(!validateHostname(label).empty());
}

// --- validateAbsolutePath ---

ATF_TEST_CASE_WITHOUT_HEAD(abspath_accepts_typical);
ATF_TEST_CASE_BODY(abspath_accepts_typical) {
  ATF_REQUIRE_EQ(validateAbsolutePath("/var/run/crate/foo.sock"), std::string());
  ATF_REQUIRE_EQ(validateAbsolutePath("/zroot/jails/alpine"), std::string());
  ATF_REQUIRE_EQ(validateAbsolutePath("/"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(abspath_rejects_relative_and_dotdot);
ATF_TEST_CASE_BODY(abspath_rejects_relative_and_dotdot) {
  ATF_REQUIRE(!validateAbsolutePath("").empty());
  ATF_REQUIRE(!validateAbsolutePath("relative/path").empty());
  ATF_REQUIRE(!validateAbsolutePath("/foo/../etc").empty());
  ATF_REQUIRE(!validateAbsolutePath("/..").empty());
  ATF_REQUIRE(!validateAbsolutePath("/foo/../bar").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(abspath_rejects_metachars);
ATF_TEST_CASE_BODY(abspath_rejects_metachars) {
  ATF_REQUIRE(!validateAbsolutePath("/foo;rm").empty());
  ATF_REQUIRE(!validateAbsolutePath("/foo`x`").empty());
  ATF_REQUIRE(!validateAbsolutePath("/foo$bar").empty());
  ATF_REQUIRE(!validateAbsolutePath("/foo|bar").empty());
  ATF_REQUIRE(!validateAbsolutePath("/foo&bar").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(abspath_dotdot_only_as_segment);
ATF_TEST_CASE_BODY(abspath_dotdot_only_as_segment) {
  // Embedded ".." inside a name is allowed; only `..` as a whole
  // path segment is rejected.
  ATF_REQUIRE_EQ(validateAbsolutePath("/foo..bar/baz"), std::string());
  ATF_REQUIRE_EQ(validateAbsolutePath("/...trihidden"), std::string());
}

// --- validateZfsDataset ---

ATF_TEST_CASE_WITHOUT_HEAD(zfs_dataset_accepts_typical);
ATF_TEST_CASE_BODY(zfs_dataset_accepts_typical) {
  ATF_REQUIRE_EQ(validateZfsDataset("zroot/jails/alpine"), std::string());
  ATF_REQUIRE_EQ(validateZfsDataset("tank/data"), std::string());
  ATF_REQUIRE_EQ(validateZfsDataset("pool/foo-1.2_3"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(zfs_dataset_rejects_edges);
ATF_TEST_CASE_BODY(zfs_dataset_rejects_edges) {
  ATF_REQUIRE(!validateZfsDataset("").empty());
  ATF_REQUIRE(!validateZfsDataset("/zroot/jails").empty());     // leading /
  ATF_REQUIRE(!validateZfsDataset("zroot/jails/").empty());      // trailing /
  ATF_REQUIRE(!validateZfsDataset("zroot//jails").empty());      // doubled /
  ATF_REQUIRE(!validateZfsDataset("zroot/foo bar").empty());     // space
  ATF_REQUIRE(!validateZfsDataset("zroot/foo;rm").empty());      // meta
}

// --- validateIfaceName ---

ATF_TEST_CASE_WITHOUT_HEAD(iface_accepts_typical);
ATF_TEST_CASE_BODY(iface_accepts_typical) {
  ATF_REQUIRE_EQ(validateIfaceName("epair0a"), std::string());
  ATF_REQUIRE_EQ(validateIfaceName("bridge0"), std::string());
  ATF_REQUIRE_EQ(validateIfaceName("igb0"), std::string());
  ATF_REQUIRE_EQ(validateIfaceName("vlan10"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(iface_rejects_edges);
ATF_TEST_CASE_BODY(iface_rejects_edges) {
  ATF_REQUIRE(!validateIfaceName("").empty());
  ATF_REQUIRE(!validateIfaceName("name with space").empty());
  ATF_REQUIRE(!validateIfaceName("name;rm").empty());
  // 16 chars exceeds IFNAMSIZ-1
  ATF_REQUIRE(!validateIfaceName("0123456789abcdef").empty());
  // 15 chars is the limit
  ATF_REQUIRE_EQ(validateIfaceName("0123456789abcde"), std::string());
}

// --- validateMacAddress ---

ATF_TEST_CASE_WITHOUT_HEAD(mac_empty_is_ok);
ATF_TEST_CASE_BODY(mac_empty_is_ok) {
  ATF_REQUIRE_EQ(validateMacAddress(""), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(mac_accepts_unicast_colon_and_dash);
ATF_TEST_CASE_BODY(mac_accepts_unicast_colon_and_dash) {
  ATF_REQUIRE_EQ(validateMacAddress("02:00:11:22:33:44"), std::string());
  ATF_REQUIRE_EQ(validateMacAddress("02-00-11-22-33-44"), std::string());
  ATF_REQUIRE_EQ(validateMacAddress("aa:bb:cc:dd:ee:ff"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(mac_rejects_multicast_bit);
ATF_TEST_CASE_BODY(mac_rejects_multicast_bit) {
  // 01:* has multicast bit set in first octet.
  ATF_REQUIRE(!validateMacAddress("01:00:11:22:33:44").empty());
  ATF_REQUIRE(!validateMacAddress("ff:ff:ff:ff:ff:ff").empty());
  ATF_REQUIRE(!validateMacAddress("33:33:00:00:00:01").empty());   // IPv6 mcast
}

ATF_TEST_CASE_WITHOUT_HEAD(mac_rejects_malformed);
ATF_TEST_CASE_BODY(mac_rejects_malformed) {
  ATF_REQUIRE(!validateMacAddress("02:00:11:22:33").empty());          // 5 octets
  ATF_REQUIRE(!validateMacAddress("02:00:11:22:33:44:55").empty());    // 7 octets
  ATF_REQUIRE(!validateMacAddress("02:00:11:22:33:gg").empty());       // non-hex
  ATF_REQUIRE(!validateMacAddress("02_00_11_22_33_44").empty());       // wrong sep
  ATF_REQUIRE(!validateMacAddress("0200.1122.3344").empty());          // cisco style
}

// --- validateIpv4Cidr ---

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_empty_is_ok);
ATF_TEST_CASE_BODY(ipv4_empty_is_ok) {
  ATF_REQUIRE_EQ(validateIpv4Cidr(""), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_accepts_typical);
ATF_TEST_CASE_BODY(ipv4_accepts_typical) {
  ATF_REQUIRE_EQ(validateIpv4Cidr("10.0.0.1/24"), std::string());
  ATF_REQUIRE_EQ(validateIpv4Cidr("192.168.1.100/32"), std::string());
  ATF_REQUIRE_EQ(validateIpv4Cidr("0.0.0.0/0"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_rejects_malformed);
ATF_TEST_CASE_BODY(ipv4_rejects_malformed) {
  ATF_REQUIRE(!validateIpv4Cidr("10.0.0.1").empty());            // no prefix
  ATF_REQUIRE(!validateIpv4Cidr("10.0.0.1/33").empty());          // prefix too big
  ATF_REQUIRE(!validateIpv4Cidr("10.0.0.256/24").empty());        // octet
  ATF_REQUIRE(!validateIpv4Cidr("10.0.0/24").empty());            // 3 octets
  ATF_REQUIRE(!validateIpv4Cidr("10.0.0.0.1/24").empty());        // 5 octets
  ATF_REQUIRE(!validateIpv4Cidr("10.0.0.01/24").empty());         // leading zero
}

// --- validateIpv6Cidr ---

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_empty_is_ok);
ATF_TEST_CASE_BODY(ipv6_empty_is_ok) {
  ATF_REQUIRE_EQ(validateIpv6Cidr(""), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_accepts_typical);
ATF_TEST_CASE_BODY(ipv6_accepts_typical) {
  ATF_REQUIRE_EQ(validateIpv6Cidr("2001:db8::1/64"), std::string());
  ATF_REQUIRE_EQ(validateIpv6Cidr("fd00::/8"), std::string());
  ATF_REQUIRE_EQ(validateIpv6Cidr("fe80::1/10"), std::string());
  ATF_REQUIRE_EQ(validateIpv6Cidr("2001:db8:0:0:0:0:0:1/128"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_rejects_malformed);
ATF_TEST_CASE_BODY(ipv6_rejects_malformed) {
  ATF_REQUIRE(!validateIpv6Cidr("2001:db8::1").empty());                   // no prefix
  ATF_REQUIRE(!validateIpv6Cidr("2001:db8::1/129").empty());               // prefix too big
  ATF_REQUIRE(!validateIpv6Cidr("2001::db8::1/64").empty());               // double ::
  ATF_REQUIRE(!validateIpv6Cidr("ggg::1/64").empty());                     // non-hex
  ATF_REQUIRE(!validateIpv6Cidr("2001:db8:0:0:0:0:0/64").empty());         // 7 groups, no ::
  ATF_REQUIRE(!validateIpv6Cidr("2001:db8:0:0:0:0:0:0:1/64").empty());     // 9 groups
}

// --- validateRuleText / validateAnchorName / validateIpfwAction ---

ATF_TEST_CASE_WITHOUT_HEAD(ruletext_accepts_single_line);
ATF_TEST_CASE_BODY(ruletext_accepts_single_line) {
  ATF_REQUIRE_EQ(validateRuleText("pass on em0 from 10.0.0.0/24"), std::string());
  ATF_REQUIRE_EQ(validateRuleText("block return all"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(ruletext_rejects_metas_and_newlines);
ATF_TEST_CASE_BODY(ruletext_rejects_metas_and_newlines) {
  ATF_REQUIRE(!validateRuleText("").empty());
  ATF_REQUIRE(!validateRuleText("rule\nrule2").empty());
  ATF_REQUIRE(!validateRuleText("rule;rm").empty());
  ATF_REQUIRE(!validateRuleText("rule`x`").empty());
  ATF_REQUIRE(!validateRuleText("rule$x").empty());
  ATF_REQUIRE(!validateRuleText("rule\\$x").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(anchor_accepts_typical_rejects_metas);
ATF_TEST_CASE_BODY(anchor_accepts_typical_rejects_metas) {
  ATF_REQUIRE_EQ(validateAnchorName("crate"), std::string());
  ATF_REQUIRE_EQ(validateAnchorName("crate.dev_pool-1"), std::string());
  // 1.1.2: '/' now allowed for pf's nested anchor convention
  // (canonical "crate/<jail>" form). pf's anchor namespace is
  // internal to the kernel, so there's no filesystem traversal
  // risk.
  ATF_REQUIRE_EQ(validateAnchorName("crate/web"), std::string());
  ATF_REQUIRE_EQ(validateAnchorName("foo/bar/baz"), std::string());
  ATF_REQUIRE(!validateAnchorName("").empty());
  ATF_REQUIRE(!validateAnchorName("foo;rm").empty());
  ATF_REQUIRE(!validateAnchorName("foo bar").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_action_closed_set);
ATF_TEST_CASE_BODY(ipfw_action_closed_set) {
  ATF_REQUIRE_EQ(validateIpfwAction("allow"), std::string());
  ATF_REQUIRE_EQ(validateIpfwAction("deny"), std::string());
  ATF_REQUIRE_EQ(validateIpfwAction("nat"), std::string());
  ATF_REQUIRE(!validateIpfwAction("ALLOW").empty());           // case-sensitive
  ATF_REQUIRE(!validateIpfwAction("permit").empty());          // not in set
  ATF_REQUIRE(!validateIpfwAction("").empty());
  ATF_REQUIRE(!validateIpfwAction("allow; rm -rf /").empty());
}

// --- Per-verb validators ---

ATF_TEST_CASE_WITHOUT_HEAD(create_jail_accepts_minimal);
ATF_TEST_CASE_BODY(create_jail_accepts_minimal) {
  CreateJailReq r;
  r.name = "alpine";
  r.path = "/zroot/jails/alpine";
  r.hostname = "alpine.local";
  r.vnet = true;
  ATF_REQUIRE_EQ(validateCreateJail(r), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(create_jail_rejects_bad_name);
ATF_TEST_CASE_BODY(create_jail_rejects_bad_name) {
  CreateJailReq r;
  r.name = "alpine;rm";
  r.path = "/zroot/jails/alpine";
  ATF_REQUIRE(!validateCreateJail(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(create_jail_rejects_bad_path);
ATF_TEST_CASE_BODY(create_jail_rejects_bad_path) {
  CreateJailReq r;
  r.name = "alpine";
  r.path = "/zroot/../etc";
  ATF_REQUIRE(!validateCreateJail(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(create_jail_empty_hostname_ok);
ATF_TEST_CASE_BODY(create_jail_empty_hostname_ok) {
  CreateJailReq r;
  r.name = "alpine";
  r.path = "/zroot/jails/alpine";
  r.hostname = "";
  ATF_REQUIRE_EQ(validateCreateJail(r), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(mount_nullfs_validates_both_paths);
ATF_TEST_CASE_BODY(mount_nullfs_validates_both_paths) {
  MountNullfsReq r;
  r.source = "/host/data";
  r.target = "/zroot/jails/alpine/data";
  ATF_REQUIRE_EQ(validateMountNullfs(r), std::string());
  r.target = "../etc";
  ATF_REQUIRE(!validateMountNullfs(r).empty());
  r.target = "/zroot/jails/alpine/data";
  r.source = "";
  ATF_REQUIRE(!validateMountNullfs(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(set_rctl_uses_retune_validators);
ATF_TEST_CASE_BODY(set_rctl_uses_retune_validators) {
  SetRctlReq r;
  r.jid = 5;
  r.key = "pcpu";
  r.rawValue = "20";
  ATF_REQUIRE_EQ(validateSetRctl(r), std::string());

  r.key = "totally-fake-key";
  ATF_REQUIRE(!validateSetRctl(r).empty());

  r.key = "pcpu";
  r.rawValue = "200"; // pcpu range 0..100
  ATF_REQUIRE(!validateSetRctl(r).empty());

  r.rawValue = "20";
  r.jid = 0;
  ATF_REQUIRE(!validateSetRctl(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(attach_zfs_requires_jid_and_dataset);
ATF_TEST_CASE_BODY(attach_zfs_requires_jid_and_dataset) {
  AttachZfsReq r;
  r.jid = 5;
  r.dataset = "zroot/jails/alpine/data";
  ATF_REQUIRE_EQ(validateAttachZfs(r), std::string());

  r.jid = -1;
  ATF_REQUIRE(!validateAttachZfs(r).empty());

  r.jid = 5;
  r.dataset = "/zroot/jails/alpine/data"; // leading slash
  ATF_REQUIRE(!validateAttachZfs(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(configure_iface_requires_at_least_one_addr);
ATF_TEST_CASE_BODY(configure_iface_requires_at_least_one_addr) {
  ConfigureIfaceReq r;
  r.jid = 7;
  r.ifname = "epair0b";
  r.bridge = "bridge0";
  r.ipv4Cidr = "10.66.1.5/24";
  ATF_REQUIRE_EQ(validateConfigureIface(r), std::string());

  // both empty -> reject
  r.ipv4Cidr.clear();
  ATF_REQUIRE(!validateConfigureIface(r).empty());

  // ipv6 only is fine
  r.ipv6Cidr = "fd00::5/64";
  ATF_REQUIRE_EQ(validateConfigureIface(r), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(configure_iface_validates_mac);
ATF_TEST_CASE_BODY(configure_iface_validates_mac) {
  ConfigureIfaceReq r;
  r.jid = 7;
  r.ifname = "epair0b";
  r.ipv4Cidr = "10.66.1.5/24";
  r.macAddr = "01:23:45:67:89:ab"; // multicast bit
  ATF_REQUIRE(!validateConfigureIface(r).empty());

  r.macAddr = "02:23:45:67:89:ab"; // unicast
  ATF_REQUIRE_EQ(validateConfigureIface(r), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(add_pf_rule_requires_anchor_and_text);
ATF_TEST_CASE_BODY(add_pf_rule_requires_anchor_and_text) {
  AddPfRuleReq r;
  r.anchor = "crate";
  r.ruleText = "pass on em0 from 10.0.0.0/24";
  ATF_REQUIRE_EQ(validateAddPfRule(r), std::string());

  r.ruleText = "rule1\nrule2";
  ATF_REQUIRE(!validateAddPfRule(r).empty());

  r.ruleText = "pass";
  r.anchor = "crate;rm";
  ATF_REQUIRE(!validateAddPfRule(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(add_ipfw_rule_validates_set_number_action);
ATF_TEST_CASE_BODY(add_ipfw_rule_validates_set_number_action) {
  AddIpfwRuleReq r;
  r.set = 0;
  r.number = 100;
  r.action = "allow";
  r.body = "ip from any to any";
  ATF_REQUIRE_EQ(validateAddIpfwRule(r), std::string());

  r.set = 32;
  ATF_REQUIRE(!validateAddIpfwRule(r).empty());

  r.set = 0;
  r.number = 0;
  ATF_REQUIRE(!validateAddIpfwRule(r).empty());

  r.number = 100;
  r.action = "permit";
  ATF_REQUIRE(!validateAddIpfwRule(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(destroy_jail_minimal);
ATF_TEST_CASE_BODY(destroy_jail_minimal) {
  DestroyJailReq r;
  r.name = "alpine";
  ATF_REQUIRE_EQ(validateDestroyJail(r), std::string());
  r.name = "../etc";
  ATF_REQUIRE(!validateDestroyJail(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(teardown_iface_minimal);
ATF_TEST_CASE_BODY(teardown_iface_minimal) {
  TeardownIfaceReq r;
  r.ifname = "epair0a";
  ATF_REQUIRE_EQ(validateTeardownIface(r), std::string());
  r.ifname = "name with space";
  ATF_REQUIRE(!validateTeardownIface(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(set_iface_up_minimal);
ATF_TEST_CASE_BODY(set_iface_up_minimal) {
  SetIfaceUpReq r;
  r.ifname = "epair0a";
  ATF_REQUIRE_EQ(validateSetIfaceUp(r), std::string());
  r.ifname = ""; // empty -> reject
  ATF_REQUIRE(!validateSetIfaceUp(r).empty());
  r.ifname = "name with space";
  ATF_REQUIRE(!validateSetIfaceUp(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(disable_iface_offload_minimal);
ATF_TEST_CASE_BODY(disable_iface_offload_minimal) {
  DisableIfaceOffloadReq r;
  r.ifname = "epair0a";
  ATF_REQUIRE_EQ(validateDisableIfaceOffload(r), std::string());
  r.ifname = "name;rm";
  ATF_REQUIRE(!validateDisableIfaceOffload(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(bridge_add_member_minimal);
ATF_TEST_CASE_BODY(bridge_add_member_minimal) {
  BridgeAddMemberReq r;
  r.bridge = "bridge0";
  r.member = "epair0a";
  ATF_REQUIRE_EQ(validateBridgeAddMember(r), std::string());
  // Empty member -> error
  r.member = "";
  std::string e = validateBridgeAddMember(r);
  ATF_REQUIRE(!e.empty());
  ATF_REQUIRE(e.find("member") != std::string::npos);
  // Empty bridge -> error
  r.bridge = "";
  r.member = "epair0a";
  e = validateBridgeAddMember(r);
  ATF_REQUIRE(!e.empty());
  ATF_REQUIRE(e.find("bridge") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(bridge_del_member_minimal);
ATF_TEST_CASE_BODY(bridge_del_member_minimal) {
  BridgeDelMemberReq r;
  r.bridge = "bridge0";
  r.member = "epair0a";
  ATF_REQUIRE_EQ(validateBridgeDelMember(r), std::string());
  r.bridge = "name with space";
  ATF_REQUIRE(!validateBridgeDelMember(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(create_epair_no_fields_required);
ATF_TEST_CASE_BODY(create_epair_no_fields_required) {
  CreateEpairReq r;
  // Validator always succeeds — no inputs to check.
  ATF_REQUIRE_EQ(validateCreateEpair(r), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(set_loginclass_rctl_validates);
ATF_TEST_CASE_BODY(set_loginclass_rctl_validates) {
  SetLoginclassRctlReq r;
  r.loginclass = "crate-1000";
  r.key = "memoryuse";
  r.rawValue = "4G";
  ATF_REQUIRE_EQ(validateSetLoginclassRctl(r), std::string());

  // Bad loginclass (no crate- prefix)
  r.loginclass = "ops";
  ATF_REQUIRE(!validateSetLoginclassRctl(r).empty());

  // Bad key (not in RCTL whitelist)
  r.loginclass = "crate-1000";
  r.key = "totally-fake-key";
  ATF_REQUIRE(!validateSetLoginclassRctl(r).empty());

  // pcpu out of range
  r.key = "pcpu";
  r.rawValue = "200";
  ATF_REQUIRE(!validateSetLoginclassRctl(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(clear_loginclass_rctl_validates);
ATF_TEST_CASE_BODY(clear_loginclass_rctl_validates) {
  ClearLoginclassRctlReq r;
  r.loginclass = "crate-1000";
  r.key = "memoryuse";
  ATF_REQUIRE_EQ(validateClearLoginclassRctl(r), std::string());

  // No value field on clear — but still validates loginclass + key
  r.loginclass = "Bad-LoginClass";
  ATF_REQUIRE(!validateClearLoginclassRctl(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(set_iface_inet_addr_minimal);
ATF_TEST_CASE_BODY(set_iface_inet_addr_minimal) {
  SetIfaceInetAddrReq r;
  r.ifname = "epair0a";
  r.addr = "10.0.0.1";
  r.prefixLen = 31;
  ATF_REQUIRE_EQ(validateSetIfaceInetAddr(r), std::string());

  // Bad iface
  r.ifname = "name;rm";
  ATF_REQUIRE(!validateSetIfaceInetAddr(r).empty());

  // Bad addr
  r.ifname = "epair0a";
  r.addr = "999.999.999.999";
  ATF_REQUIRE(!validateSetIfaceInetAddr(r).empty());

  // Out-of-range prefix
  r.addr = "10.0.0.1";
  r.prefixLen = 33;
  ATF_REQUIRE(!validateSetIfaceInetAddr(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(reclaim_iface_from_vnet_minimal);
ATF_TEST_CASE_BODY(reclaim_iface_from_vnet_minimal) {
  ReclaimIfaceFromVnetReq r;
  r.ifname = "em0";
  r.jailName = "web";
  ATF_REQUIRE_EQ(validateReclaimIfaceFromVnet(r), std::string());

  // Bad ifname (shell metachar)
  r.ifname = "em0; rm -rf /";
  ATF_REQUIRE(!validateReclaimIfaceFromVnet(r).empty());

  // Bad jail name
  r.ifname = "em0";
  r.jailName = "../etc/passwd";
  ATF_REQUIRE(!validateReclaimIfaceFromVnet(r).empty());

  // Empty ifname
  r.ifname = "";
  r.jailName = "web";
  ATF_REQUIRE(!validateReclaimIfaceFromVnet(r).empty());

  // Empty jail name
  r.ifname = "em0";
  r.jailName = "";
  ATF_REQUIRE(!validateReclaimIfaceFromVnet(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(flush_pf_anchor_minimal);
ATF_TEST_CASE_BODY(flush_pf_anchor_minimal) {
  FlushPfAnchorReq r;

  // Canonical "crate/<jail>" nested anchor form — the real-world
  // shape produced by lib/run.cpp's per-container firewall and
  // auto-fw paths. Requires the 1.1.2 validateAnchorName fix.
  r.anchor = "crate/web";
  ATF_REQUIRE_EQ(validateFlushPfAnchor(r), std::string());

  // Plain anchor name (no slash) also valid.
  r.anchor = "crate";
  ATF_REQUIRE_EQ(validateFlushPfAnchor(r), std::string());

  // Empty anchor.
  r.anchor = "";
  ATF_REQUIRE(!validateFlushPfAnchor(r).empty());

  // Shell metachar still rejected — '/' allowance does NOT relax
  // the character whitelist for ';', space, '`', etc.
  r.anchor = "crate; pfctl -F all";
  ATF_REQUIRE(!validateFlushPfAnchor(r).empty());

  r.anchor = "crate web";
  ATF_REQUIRE(!validateFlushPfAnchor(r).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(query_jail_rctl_minimal);
ATF_TEST_CASE_BODY(query_jail_rctl_minimal) {
  QueryJailRctlReq r;
  r.jid = 42;
  ATF_REQUIRE_EQ(validateQueryJailRctl(r), std::string());

  // jid=1 (lowest valid jid)
  r.jid = 1;
  ATF_REQUIRE_EQ(validateQueryJailRctl(r), std::string());

  // jid=65535 (highest valid)
  r.jid = 65535;
  ATF_REQUIRE_EQ(validateQueryJailRctl(r), std::string());

  // jid=0 — invalid (jail(8) starts at jid=1)
  r.jid = 0;
  ATF_REQUIRE(!validateQueryJailRctl(r).empty());

  // jid out of range
  r.jid = 70000;
  ATF_REQUIRE(!validateQueryJailRctl(r).empty());
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, verb_token_roundtrips_for_every_verb);
  ATF_ADD_TEST_CASE(tcs, verb_unknown_token_returns_unknown);
  ATF_ADD_TEST_CASE(tcs, verb_tokens_are_snake_case_lowercase);

  ATF_ADD_TEST_CASE(tcs, jailname_accepts_typical);
  ATF_ADD_TEST_CASE(tcs, jailname_rejects_empty_and_reserved);
  ATF_ADD_TEST_CASE(tcs, jailname_rejects_metas);
  ATF_ADD_TEST_CASE(tcs, jailname_rejects_too_long);
  ATF_ADD_TEST_CASE(tcs, jailname_accepts_runtime_pid_suffix);

  ATF_ADD_TEST_CASE(tcs, hostname_empty_is_ok);
  ATF_ADD_TEST_CASE(tcs, hostname_accepts_typical);
  ATF_ADD_TEST_CASE(tcs, hostname_rejects_label_edge_cases);
  ATF_ADD_TEST_CASE(tcs, hostname_rejects_long_label);

  ATF_ADD_TEST_CASE(tcs, abspath_accepts_typical);
  ATF_ADD_TEST_CASE(tcs, abspath_rejects_relative_and_dotdot);
  ATF_ADD_TEST_CASE(tcs, abspath_rejects_metachars);
  ATF_ADD_TEST_CASE(tcs, abspath_dotdot_only_as_segment);

  ATF_ADD_TEST_CASE(tcs, zfs_dataset_accepts_typical);
  ATF_ADD_TEST_CASE(tcs, zfs_dataset_rejects_edges);

  ATF_ADD_TEST_CASE(tcs, iface_accepts_typical);
  ATF_ADD_TEST_CASE(tcs, iface_rejects_edges);

  ATF_ADD_TEST_CASE(tcs, mac_empty_is_ok);
  ATF_ADD_TEST_CASE(tcs, mac_accepts_unicast_colon_and_dash);
  ATF_ADD_TEST_CASE(tcs, mac_rejects_multicast_bit);
  ATF_ADD_TEST_CASE(tcs, mac_rejects_malformed);

  ATF_ADD_TEST_CASE(tcs, ipv4_empty_is_ok);
  ATF_ADD_TEST_CASE(tcs, ipv4_accepts_typical);
  ATF_ADD_TEST_CASE(tcs, ipv4_rejects_malformed);

  ATF_ADD_TEST_CASE(tcs, ipv6_empty_is_ok);
  ATF_ADD_TEST_CASE(tcs, ipv6_accepts_typical);
  ATF_ADD_TEST_CASE(tcs, ipv6_rejects_malformed);

  ATF_ADD_TEST_CASE(tcs, ruletext_accepts_single_line);
  ATF_ADD_TEST_CASE(tcs, ruletext_rejects_metas_and_newlines);
  ATF_ADD_TEST_CASE(tcs, anchor_accepts_typical_rejects_metas);
  ATF_ADD_TEST_CASE(tcs, ipfw_action_closed_set);

  ATF_ADD_TEST_CASE(tcs, create_jail_accepts_minimal);
  ATF_ADD_TEST_CASE(tcs, create_jail_rejects_bad_name);
  ATF_ADD_TEST_CASE(tcs, create_jail_rejects_bad_path);
  ATF_ADD_TEST_CASE(tcs, create_jail_empty_hostname_ok);
  ATF_ADD_TEST_CASE(tcs, mount_nullfs_validates_both_paths);
  ATF_ADD_TEST_CASE(tcs, set_rctl_uses_retune_validators);
  ATF_ADD_TEST_CASE(tcs, attach_zfs_requires_jid_and_dataset);
  ATF_ADD_TEST_CASE(tcs, configure_iface_requires_at_least_one_addr);
  ATF_ADD_TEST_CASE(tcs, configure_iface_validates_mac);
  ATF_ADD_TEST_CASE(tcs, add_pf_rule_requires_anchor_and_text);
  ATF_ADD_TEST_CASE(tcs, add_ipfw_rule_validates_set_number_action);
  ATF_ADD_TEST_CASE(tcs, destroy_jail_minimal);
  ATF_ADD_TEST_CASE(tcs, teardown_iface_minimal);
  ATF_ADD_TEST_CASE(tcs, set_iface_up_minimal);
  ATF_ADD_TEST_CASE(tcs, disable_iface_offload_minimal);
  ATF_ADD_TEST_CASE(tcs, bridge_add_member_minimal);
  ATF_ADD_TEST_CASE(tcs, bridge_del_member_minimal);
  ATF_ADD_TEST_CASE(tcs, set_iface_inet_addr_minimal);
  ATF_ADD_TEST_CASE(tcs, create_epair_no_fields_required);
  ATF_ADD_TEST_CASE(tcs, set_loginclass_rctl_validates);
  ATF_ADD_TEST_CASE(tcs, clear_loginclass_rctl_validates);
  ATF_ADD_TEST_CASE(tcs, reclaim_iface_from_vnet_minimal);
  ATF_ADD_TEST_CASE(tcs, flush_pf_anchor_minimal);
  ATF_ADD_TEST_CASE(tcs, query_jail_rctl_minimal);
}
