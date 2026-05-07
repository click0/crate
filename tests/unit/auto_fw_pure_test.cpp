// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "auto_fw_pure.h"

#include <atf-c++.hpp>

#include <set>
#include <string>

using AutoFwPure::RedirPort;
using AutoFwPure::buildIpfwNatConfigArgv;
using AutoFwPure::buildIpfwNatConfigWithRedirsArgv;
using AutoFwPure::buildIpfwNatDeleteArgv;
using AutoFwPure::buildIpfwNatRuleArgv;
using AutoFwPure::buildIpfwRuleDeleteArgv;
using AutoFwPure::formatRdrAnchorLine;
using AutoFwPure::formatRdrRule;
using AutoFwPure::formatSnatAnchorLine;
using AutoFwPure::formatSnatRule;
using AutoFwPure::natIdForJail;
using AutoFwPure::ruleIdForJail;
using AutoFwPure::validateExternalIface;
using AutoFwPure::validateIpfwNatId;
using AutoFwPure::validatePort;
using AutoFwPure::validateProto;
using AutoFwPure::validateRuleAddress;

// ----------------------------------------------------------------------
// Iface validator
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(iface_typical_accepted);
ATF_TEST_CASE_BODY(iface_typical_accepted) {
  ATF_REQUIRE_EQ(validateExternalIface("em0"),       std::string());
  ATF_REQUIRE_EQ(validateExternalIface("igb0"),      std::string());
  ATF_REQUIRE_EQ(validateExternalIface("vlan0.100"), std::string());
  ATF_REQUIRE_EQ(validateExternalIface("bridge0"),   std::string());
  ATF_REQUIRE_EQ(validateExternalIface("vtnet1"),    std::string());
  ATF_REQUIRE_EQ(validateExternalIface("a"),         std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(iface_invalid_rejected);
ATF_TEST_CASE_BODY(iface_invalid_rejected) {
  ATF_REQUIRE(!validateExternalIface("").empty());
  ATF_REQUIRE(!validateExternalIface(std::string(16, 'a')).empty());  // > IFNAMSIZ-1
  ATF_REQUIRE(!validateExternalIface("em 0").empty());                 // space
  ATF_REQUIRE(!validateExternalIface("em0;rm").empty());               // semicolon
  ATF_REQUIRE(!validateExternalIface("em0`pwd`").empty());             // backtick
  ATF_REQUIRE(!validateExternalIface("em0/em1").empty());              // slash
  ATF_REQUIRE(!validateExternalIface("em\n0").empty());                // newline
}

// ----------------------------------------------------------------------
// Address validator
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(address_typical_accepted);
ATF_TEST_CASE_BODY(address_typical_accepted) {
  ATF_REQUIRE_EQ(validateRuleAddress("10.66.0.5"),       std::string());
  ATF_REQUIRE_EQ(validateRuleAddress("10.66.0.0/24"),    std::string());
  ATF_REQUIRE_EQ(validateRuleAddress("192.168.1.1"),     std::string());
  ATF_REQUIRE_EQ(validateRuleAddress("172.16.0.0/12"),   std::string());
  ATF_REQUIRE_EQ(validateRuleAddress("0.0.0.0/0"),       std::string());  // catch-all
}

ATF_TEST_CASE_WITHOUT_HEAD(address_invalid_rejected);
ATF_TEST_CASE_BODY(address_invalid_rejected) {
  ATF_REQUIRE(!validateRuleAddress("").empty());
  // Shell-injection attempts.
  ATF_REQUIRE(!validateRuleAddress("10.66.0.5; rm -rf /").empty());
  ATF_REQUIRE(!validateRuleAddress("10.66.0.5`pwd`").empty());
  ATF_REQUIRE(!validateRuleAddress("$(id)").empty());
  // Non-numeric chars.
  ATF_REQUIRE(!validateRuleAddress("ten.dot.zero.five").empty());
  // Multiple slashes.
  ATF_REQUIRE(!validateRuleAddress("10.66.0.0/24/8").empty());
  // Way too long.
  ATF_REQUIRE(!validateRuleAddress(std::string(50, '1')).empty());
}

// ----------------------------------------------------------------------
// formatSnatRule
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(snat_rule_shape_single_ip);
ATF_TEST_CASE_BODY(snat_rule_shape_single_ip) {
  // Single-IP form (used per-jail with the allocator).
  ATF_REQUIRE_EQ(formatSnatRule("em0", "10.66.0.5"),
                 std::string("nat on em0 inet from 10.66.0.5 to ! 10.66.0.5 -> (em0)"));
}

ATF_TEST_CASE_WITHOUT_HEAD(snat_rule_shape_cidr);
ATF_TEST_CASE_BODY(snat_rule_shape_cidr) {
  // Pool-wide form (could be used for one rule covering the whole
  // pool rather than per-jail; we keep it formatable but don't use
  // it in the runtime today).
  ATF_REQUIRE_EQ(formatSnatRule("igb0", "10.66.0.0/24"),
                 std::string("nat on igb0 inet from 10.66.0.0/24 to ! 10.66.0.0/24 -> (igb0)"));
}

ATF_TEST_CASE_WITHOUT_HEAD(snat_rule_inet_token_present);
ATF_TEST_CASE_BODY(snat_rule_inet_token_present) {
  // "inet" qualifier ensures the rule is IPv4-only — without it,
  // pf would also try to match IPv6 and complain (pre-13 behaviour).
  // Pin the token so a future re-format doesn't accidentally drop it.
  auto r = formatSnatRule("em0", "10.66.0.5");
  ATF_REQUIRE(r.find(" inet from ") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(snat_rule_excludes_intra_pool_traffic);
ATF_TEST_CASE_BODY(snat_rule_excludes_intra_pool_traffic) {
  // The "to ! <jailAddr>" segment prevents intra-jail traffic from
  // being NAT'd. A typo here would silently break jail-to-jail
  // routing on the same bridge — pin the format.
  auto r = formatSnatRule("em0", "10.66.0.5");
  ATF_REQUIRE(r.find(" to ! 10.66.0.5 ") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(snat_rule_uses_iface_token);
ATF_TEST_CASE_BODY(snat_rule_uses_iface_token) {
  // "(<iface>)" with parens means "translate to whatever address
  // is currently on <iface>" — robust against DHCP lease changes.
  // Without parens, pf would lock the rule to the IP at the time
  // the rule was added.
  auto r = formatSnatRule("em0", "10.66.0.5");
  ATF_REQUIRE(r.find("-> (em0)") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(anchor_line_has_trailing_newline);
ATF_TEST_CASE_BODY(anchor_line_has_trailing_newline) {
  // formatSnatAnchorLine adds a trailing \n so multiple lines
  // concatenate cleanly when caller builds the rules text.
  auto line = formatSnatAnchorLine("em0", "10.66.0.5");
  ATF_REQUIRE_EQ(line.back(), '\n');
}

ATF_TEST_CASE_WITHOUT_HEAD(anchor_line_starts_with_rule);
ATF_TEST_CASE_BODY(anchor_line_starts_with_rule) {
  auto line = formatSnatAnchorLine("em0", "10.66.0.5");
  ATF_REQUIRE(line.find("nat on em0 inet from 10.66.0.5") == 0u);
}

// ----------------------------------------------------------------------
// Proto + port validators (0.8.1 — port-forward)
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(proto_typical);
ATF_TEST_CASE_BODY(proto_typical) {
  ATF_REQUIRE_EQ(validateProto("tcp"), std::string());
  ATF_REQUIRE_EQ(validateProto("udp"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(proto_invalid);
ATF_TEST_CASE_BODY(proto_invalid) {
  ATF_REQUIRE(!validateProto("").empty());
  ATF_REQUIRE(!validateProto("TCP").empty());     // case-sensitive — pf lowercase
  ATF_REQUIRE(!validateProto("icmp").empty());    // not supported in v1
  ATF_REQUIRE(!validateProto("tcp;rm").empty());  // injection
}

ATF_TEST_CASE_WITHOUT_HEAD(port_typical);
ATF_TEST_CASE_BODY(port_typical) {
  ATF_REQUIRE_EQ(validatePort(80),    std::string());
  ATF_REQUIRE_EQ(validatePort(443),   std::string());
  ATF_REQUIRE_EQ(validatePort(8080),  std::string());
  ATF_REQUIRE_EQ(validatePort(65535), std::string());
  ATF_REQUIRE_EQ(validatePort(1),     std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(port_invalid);
ATF_TEST_CASE_BODY(port_invalid) {
  ATF_REQUIRE(!validatePort(0).empty());           // port 0 reserved
  ATF_REQUIRE(!validatePort(65536).empty());       // > 16-bit
  ATF_REQUIRE(!validatePort(100000).empty());
}

// ----------------------------------------------------------------------
// formatRdrRule — single port and range forms
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(rdr_single_port_shape);
ATF_TEST_CASE_BODY(rdr_single_port_shape) {
  // Single port both sides — emit "port 8080" not "port 8080:8080".
  ATF_REQUIRE_EQ(formatRdrRule("em0", "tcp", 8080, 8080,
                               "10.66.0.5", 80, 80),
                 std::string("rdr on em0 inet proto tcp from any to (em0) "
                             "port 8080 -> 10.66.0.5 port 80"));
}

ATF_TEST_CASE_WITHOUT_HEAD(rdr_range_both_sides);
ATF_TEST_CASE_BODY(rdr_range_both_sides) {
  ATF_REQUIRE_EQ(formatRdrRule("em0", "udp", 5000, 5099,
                               "10.66.0.7", 5000, 5099),
                 std::string("rdr on em0 inet proto udp from any to (em0) "
                             "port 5000:5099 -> 10.66.0.7 port 5000:5099"));
}

ATF_TEST_CASE_WITHOUT_HEAD(rdr_range_host_single_jail);
ATF_TEST_CASE_BODY(rdr_range_host_single_jail) {
  // Asymmetric: host range -> single jail port. pf accepts both
  // forms; the rule still parses.
  auto r = formatRdrRule("em0", "tcp", 8000, 8010,
                         "10.66.0.5", 80, 80);
  ATF_REQUIRE(r.find("port 8000:8010 ->") != std::string::npos);
  ATF_REQUIRE(r.find("port 80")           != std::string::npos);
  ATF_REQUIRE(r.find("port 80:80")        == std::string::npos);  // collapsed
}

ATF_TEST_CASE_WITHOUT_HEAD(rdr_uses_iface_token_for_dest);
ATF_TEST_CASE_BODY(rdr_uses_iface_token_for_dest) {
  // "(em0)" with parens — match whatever address is currently on
  // em0. Robust against DHCP lease changes.
  auto r = formatRdrRule("em0", "tcp", 8080, 8080,
                         "10.66.0.5", 80, 80);
  ATF_REQUIRE(r.find("to (em0) port") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(rdr_inet_qualifier_present);
ATF_TEST_CASE_BODY(rdr_inet_qualifier_present) {
  // Same IPv4-only invariant as SNAT.
  auto r = formatRdrRule("em0", "tcp", 8080, 8080,
                         "10.66.0.5", 80, 80);
  ATF_REQUIRE(r.find(" inet proto tcp ") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(rdr_anchor_line_has_trailing_newline);
ATF_TEST_CASE_BODY(rdr_anchor_line_has_trailing_newline) {
  auto line = formatRdrAnchorLine("em0", "tcp", 8080, 8080,
                                   "10.66.0.5", 80, 80);
  ATF_REQUIRE_EQ(line.back(), '\n');
  ATF_REQUIRE(line.find("rdr on em0") == 0u);
}

// ----------------------------------------------------------------------
// ipfw backend (0.8.2)
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_ids_deterministic_per_jid);
ATF_TEST_CASE_BODY(ipfw_ids_deterministic_per_jid) {
  // Two calls with the same JID return the same IDs — required for
  // idempotent re-runs (and for cleanup to find the right rule).
  ATF_REQUIRE_EQ(natIdForJail(5),  natIdForJail(5));
  ATF_REQUIRE_EQ(ruleIdForJail(5), ruleIdForJail(5));
  // Different JIDs map to different IDs.
  ATF_REQUIRE(natIdForJail(5)  != natIdForJail(6));
  ATF_REQUIRE(ruleIdForJail(5) != ruleIdForJail(6));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_ids_in_reserved_ranges);
ATF_TEST_CASE_BODY(ipfw_ids_in_reserved_ranges) {
  // NAT base 30000, rule base 40000 — leaves low IDs for operator
  // rules. Throttle (0.7.7) uses 10000+pipe / 20000+rule, so our
  // 30000+/40000+ don't collide.
  ATF_REQUIRE_EQ(natIdForJail(0),  30000u);
  ATF_REQUIRE_EQ(ruleIdForJail(0), 40000u);
  ATF_REQUIRE_EQ(natIdForJail(42),  30042u);
  ATF_REQUIRE_EQ(ruleIdForJail(42), 40042u);
}

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_validate_id_range);
ATF_TEST_CASE_BODY(ipfw_validate_id_range) {
  // Belt: cap at 16-bit.
  ATF_REQUIRE_EQ(validateIpfwNatId(30000), std::string());
  ATF_REQUIRE_EQ(validateIpfwNatId(40000), std::string());
  ATF_REQUIRE(!validateIpfwNatId(0).empty());        // below base
  ATF_REQUIRE(!validateIpfwNatId(29999).empty());    // below base
  ATF_REQUIRE(!validateIpfwNatId(70000).empty());    // > 16-bit
}

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_nat_config_argv_shape);
ATF_TEST_CASE_BODY(ipfw_nat_config_argv_shape) {
  // ipfw nat <id> config if <iface>
  auto v = buildIpfwNatConfigArgv(30005, "em0");
  ATF_REQUIRE_EQ(v.size(), (size_t)6);
  ATF_REQUIRE_EQ(v[0], std::string("/sbin/ipfw"));
  ATF_REQUIRE_EQ(v[1], std::string("nat"));
  ATF_REQUIRE_EQ(v[2], std::string("30005"));
  ATF_REQUIRE_EQ(v[3], std::string("config"));
  ATF_REQUIRE_EQ(v[4], std::string("if"));
  ATF_REQUIRE_EQ(v[5], std::string("em0"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_nat_rule_argv_shape);
ATF_TEST_CASE_BODY(ipfw_nat_rule_argv_shape) {
  // ipfw add <ruleId> nat <natId> ip from <jailAddr> to any out via <iface>
  auto v = buildIpfwNatRuleArgv(40005, 30005, "10.66.0.5", "em0");
  ATF_REQUIRE_EQ(v[0], std::string("/sbin/ipfw"));
  ATF_REQUIRE_EQ(v[1], std::string("add"));
  ATF_REQUIRE_EQ(v[2], std::string("40005"));
  ATF_REQUIRE_EQ(v[3], std::string("nat"));
  ATF_REQUIRE_EQ(v[4], std::string("30005"));
  // Pin the from/to/out/via tokens — operator-readable & ipfw-strict.
  bool sawFrom = false, sawTo = false, sawOut = false, sawVia = false;
  for (const auto &a : v) {
    if (a == "from") sawFrom = true;
    if (a == "to")   sawTo   = true;
    if (a == "out")  sawOut  = true;
    if (a == "via")  sawVia  = true;
  }
  ATF_REQUIRE(sawFrom);
  ATF_REQUIRE(sawTo);
  ATF_REQUIRE(sawOut);
  ATF_REQUIRE(sawVia);
}

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_delete_argvs);
ATF_TEST_CASE_BODY(ipfw_delete_argvs) {
  // ipfw delete <ruleId>
  auto rd = buildIpfwRuleDeleteArgv(40005);
  ATF_REQUIRE_EQ(rd.size(), (size_t)3);
  ATF_REQUIRE_EQ(rd[0], std::string("/sbin/ipfw"));
  ATF_REQUIRE_EQ(rd[1], std::string("delete"));
  ATF_REQUIRE_EQ(rd[2], std::string("40005"));

  // ipfw nat <natId> delete  (note: "delete" is LAST, mirrors
  // the throttle-pipe-delete word-order quirk we documented in 0.7.7).
  auto nd = buildIpfwNatDeleteArgv(30005);
  ATF_REQUIRE_EQ(nd.size(), (size_t)4);
  ATF_REQUIRE_EQ(nd[0], std::string("/sbin/ipfw"));
  ATF_REQUIRE_EQ(nd[1], std::string("nat"));
  ATF_REQUIRE_EQ(nd[2], std::string("30005"));
  ATF_REQUIRE_EQ(nd[3], std::string("delete"));
}

// ----------------------------------------------------------------------
// ipfw redir_port (0.8.3) — closes the pf/ipfw symmetry gap from 0.8.2
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_nat_with_no_redirs_equivalent_to_basic);
ATF_TEST_CASE_BODY(ipfw_nat_with_no_redirs_equivalent_to_basic) {
  // Empty redirs must produce the same argv as the basic SNAT-only
  // form; otherwise 0.8.3 would silently change 0.8.2 behaviour.
  // (Element-wise compare because ATF_REQUIRE_EQ on vector tries to
  // operator<< the vector for the failure message.)
  auto basic = buildIpfwNatConfigArgv(30005, "em0");
  auto empty = buildIpfwNatConfigWithRedirsArgv(30005, "em0", {});
  ATF_REQUIRE_EQ(basic.size(), empty.size());
  for (std::size_t i = 0; i < basic.size(); i++)
    ATF_REQUIRE_EQ(basic[i], empty[i]);
}

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_nat_redir_single_port);
ATF_TEST_CASE_BODY(ipfw_nat_redir_single_port) {
  std::vector<RedirPort> redirs = {
    {"tcp", 8080, 8080, "10.66.0.5", 80, 80},
  };
  auto v = buildIpfwNatConfigWithRedirsArgv(30005, "em0", redirs);
  // ipfw nat 30005 config if em0 redir_port tcp 10.66.0.5:80 8080
  ATF_REQUIRE_EQ(v.size(), (size_t)10);
  ATF_REQUIRE_EQ(v[6], std::string("redir_port"));
  ATF_REQUIRE_EQ(v[7], std::string("tcp"));
  ATF_REQUIRE_EQ(v[8], std::string("10.66.0.5:80"));
  ATF_REQUIRE_EQ(v[9], std::string("8080"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_nat_redir_range);
ATF_TEST_CASE_BODY(ipfw_nat_redir_range) {
  std::vector<RedirPort> redirs = {
    {"udp", 5000, 5099, "10.66.0.7", 5000, 5099},
  };
  auto v = buildIpfwNatConfigWithRedirsArgv(30005, "em0", redirs);
  ATF_REQUIRE_EQ(v[7], std::string("udp"));
  ATF_REQUIRE_EQ(v[8], std::string("10.66.0.7:5000-5099"));
  ATF_REQUIRE_EQ(v[9], std::string("5000-5099"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_nat_redir_asymmetric_range);
ATF_TEST_CASE_BODY(ipfw_nat_redir_asymmetric_range) {
  // Host range -> single jail port. Jail side collapses; host side
  // stays as range. Same shape as the pf rdr asymmetric case.
  std::vector<RedirPort> redirs = {
    {"tcp", 8000, 8010, "10.66.0.5", 80, 80},
  };
  auto v = buildIpfwNatConfigWithRedirsArgv(30005, "em0", redirs);
  ATF_REQUIRE_EQ(v[8], std::string("10.66.0.5:80"));     // jail collapsed
  ATF_REQUIRE_EQ(v[9], std::string("8000-8010"));         // host range
}

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_nat_redir_multiple);
ATF_TEST_CASE_BODY(ipfw_nat_redir_multiple) {
  // Multiple redirects on one config command — chains of
  // redir_port clauses go on the same `ipfw nat ... config` line.
  std::vector<RedirPort> redirs = {
    {"tcp", 8080, 8080, "10.66.0.5", 80,    80},
    {"udp", 53,   53,   "10.66.0.5", 53,    53},
    {"tcp", 5000, 5099, "10.66.0.5", 5000,  5099},
  };
  auto v = buildIpfwNatConfigWithRedirsArgv(30005, "em0", redirs);
  // Each redir_port adds 4 tokens; check totals + count of clauses.
  // 6 base tokens + 3 redirs * 4 tokens = 18.
  ATF_REQUIRE_EQ(v.size(), (size_t)18);
  unsigned redirPortCount = 0;
  for (const auto &t : v)
    if (t == "redir_port") redirPortCount++;
  ATF_REQUIRE_EQ(redirPortCount, 3u);
}

// --- 0.8.37: orphan-rule scan tests ---

ATF_TEST_CASE_WITHOUT_HEAD(orphan_rules_picks_non_running);
ATF_TEST_CASE_BODY(orphan_rules_picks_non_running) {
  // jids 5 and 7 are running; rules at 40005 + 40007 valid,
  // 40009 + 40012 are orphans.
  std::set<int> running{5, 7};
  std::string out =
    "40005 nat 30005 ip from 10.66.0.5 to any out via em0\n"
    "40007 nat 30007 ip from 10.66.0.7 to any out via em0\n"
    "40009 nat 30009 ip from 10.66.0.9 to any out via em0\n"
    "40012 nat 30012 ip from 10.66.0.12 to any out via em0\n";
  auto orphans = AutoFwPure::pickOrphanIpfwRulesByJid(out, running);
  ATF_REQUIRE_EQ(orphans.size(), (size_t)2);
  ATF_REQUIRE_EQ(orphans[0], 40009u);
  ATF_REQUIRE_EQ(orphans[1], 40012u);
}

ATF_TEST_CASE_WITHOUT_HEAD(orphan_rules_skips_out_of_range);
ATF_TEST_CASE_BODY(orphan_rules_skips_out_of_range) {
  // 0.8.39: scan now narrowed from "anything in 40000-49999" to
  // the specific sub-ranges crate actually populates:
  //   40000-40999  main NAT-activation rule (40000+jid)
  //   41000-41999  host-loopback hairpin rule (41000+jid)
  // Other rules in the broader 40000-49999 are operator-managed
  // strays — left alone, NOT flagged as orphans.
  std::set<int> running;   // none running
  std::string out =
    "100 allow ip from any to any\n"
    "39999 allow ip from any to any\n"   // below crate range
    "40000 allow ip from any to any\n"   // jid 0 = orphan (crate main)
    "41005 allow ip from any to any\n"   // jid 5 = orphan (crate loopback)
    "42000 allow ip from any to any\n"   // unknown crate sub-range; skip
    "49999 allow ip from any to any\n"   // unknown crate sub-range; skip
    "50000 allow ip from any to any\n"   // above crate range
    "60000 allow ip from any to any\n";
  auto orphans = AutoFwPure::pickOrphanIpfwRulesByJid(out, running);
  ATF_REQUIRE_EQ(orphans.size(), (size_t)2);
  ATF_REQUIRE_EQ(orphans[0], 40000u);
  ATF_REQUIRE_EQ(orphans[1], 41005u);
}

ATF_TEST_CASE_WITHOUT_HEAD(orphan_rules_handles_crlf_blanks);
ATF_TEST_CASE_BODY(orphan_rules_handles_crlf_blanks) {
  std::set<int> running;
  std::string out =
    "\r\n"
    "40001 nat 30001 ip from 10.66.0.1 to any out via em0\r\n"
    "\n"
    "header without rule num\r\n"
    "40002 nat 30002 ip from 10.66.0.2 to any out via em0\r\n";
  auto orphans = AutoFwPure::pickOrphanIpfwRulesByJid(out, running);
  ATF_REQUIRE_EQ(orphans.size(), (size_t)2);
  ATF_REQUIRE_EQ(orphans[0], 40001u);
  ATF_REQUIRE_EQ(orphans[1], 40002u);
}

ATF_TEST_CASE_WITHOUT_HEAD(orphan_throttle_pair_jid_division);
ATF_TEST_CASE_BODY(orphan_throttle_pair_jid_division) {
  // Throttle uses (20000+jid*2, 20000+jid*2+1). jid 5 -> 20010,20011.
  // running={5}: 20010+20011 valid; 20020 (jid=10) is orphan.
  std::set<int> running{5};
  std::string out =
    "20010 pipe 10010 ip from any to any\n"
    "20011 pipe 10011 ip from any to any\n"
    "20020 pipe 10020 ip from any to any\n"   // jid 10 = orphan
    "20021 pipe 10021 ip from any to any\n";  // jid 10 = orphan
  auto orphans = AutoFwPure::pickOrphanIpfwThrottleRulesByJid(out, running);
  ATF_REQUIRE_EQ(orphans.size(), (size_t)2);
  ATF_REQUIRE_EQ(orphans[0], 20020u);
  ATF_REQUIRE_EQ(orphans[1], 20021u);
}

ATF_TEST_CASE_WITHOUT_HEAD(orphan_nat_ids_basic);
ATF_TEST_CASE_BODY(orphan_nat_ids_basic) {
  std::set<int> running{5};   // jid 5 running -> 30005 valid
  std::string out =
    "ipfw nat 30005 config if em0\n"
    "ipfw nat 30009 config if em0\n"   // jid 9 orphan
    "ipfw nat 30012 config if em0 redir_port tcp 10.66.0.12:80 8080\n";
  auto orphans = AutoFwPure::pickOrphanIpfwNatIds(out, running);
  ATF_REQUIRE_EQ(orphans.size(), (size_t)2);
  ATF_REQUIRE_EQ(orphans[0], 30009u);
  ATF_REQUIRE_EQ(orphans[1], 30012u);
}

// --- 0.8.39: bug#239590 host-loopback hairpin ---

ATF_TEST_CASE_WITHOUT_HEAD(loopback_rule_id_distinct_from_main);
ATF_TEST_CASE_BODY(loopback_rule_id_distinct_from_main) {
  // Same jid -> different rule IDs in different sub-ranges.
  for (int jid = 1; jid <= 100; jid++) {
    auto main = AutoFwPure::ruleIdForJail(jid);
    auto loop = AutoFwPure::loopbackRuleIdForJail(jid);
    ATF_REQUIRE(main != loop);
    ATF_REQUIRE(loop > main);
    ATF_REQUIRE(loop - main == 1000);
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(loopback_argv_shape);
ATF_TEST_CASE_BODY(loopback_argv_shape) {
  auto argv = AutoFwPure::buildIpfwHostLoopbackNatArgv(41005, 30005);
  ATF_REQUIRE_EQ(argv.size(), (size_t)10);
  ATF_REQUIRE_EQ(argv[0], std::string("/sbin/ipfw"));
  ATF_REQUIRE_EQ(argv[1], std::string("add"));
  ATF_REQUIRE_EQ(argv[2], std::string("41005"));
  ATF_REQUIRE_EQ(argv[3], std::string("nat"));
  ATF_REQUIRE_EQ(argv[4], std::string("30005"));
  ATF_REQUIRE_EQ(argv[5], std::string("tcp"));
  ATF_REQUIRE_EQ(argv[6], std::string("from"));
  ATF_REQUIRE_EQ(argv[7], std::string("me"));
  ATF_REQUIRE_EQ(argv[8], std::string("to"));
  ATF_REQUIRE_EQ(argv[9], std::string("me"));
}

ATF_TEST_CASE_WITHOUT_HEAD(orphan_scan_recognises_loopback_range);
ATF_TEST_CASE_BODY(orphan_scan_recognises_loopback_range) {
  // jid 5 running -> 40005 (main) + 41005 (loopback) both valid.
  // jid 9 not running -> 40009 + 41009 both orphans.
  std::set<int> running{5};
  std::string out =
    "40005 nat 30005 ip from 10.66.0.5 to any out via em0\n"
    "41005 nat 30005 tcp from me to me\n"
    "40009 nat 30009 ip from 10.66.0.9 to any out via em0\n"
    "41009 nat 30009 tcp from me to me\n";
  auto orphans = AutoFwPure::pickOrphanIpfwRulesByJid(out, running);
  ATF_REQUIRE_EQ(orphans.size(), (size_t)2);
  ATF_REQUIRE_EQ(orphans[0], 40009u);
  ATF_REQUIRE_EQ(orphans[1], 41009u);
}

ATF_TEST_CASE_WITHOUT_HEAD(orphan_nat_ids_skips_non_nat_lines);
ATF_TEST_CASE_BODY(orphan_nat_ids_skips_non_nat_lines) {
  std::set<int> running;
  std::string out =
    "header line\n"
    "ipfw nat 30001 config if em0\n"
    "ipfw add 100 allow ip from any to any\n"   // not a nat line
    "ipfw nat abc config if em0\n"               // non-numeric
    "ipfw nat 29999 config if em0\n"             // below range
    "ipfw nat 40000 config if em0\n";            // above range
  auto orphans = AutoFwPure::pickOrphanIpfwNatIds(out, running);
  ATF_REQUIRE_EQ(orphans.size(), (size_t)1);
  ATF_REQUIRE_EQ(orphans[0], 30001u);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, iface_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, iface_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, address_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, address_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, snat_rule_shape_single_ip);
  ATF_ADD_TEST_CASE(tcs, snat_rule_shape_cidr);
  ATF_ADD_TEST_CASE(tcs, snat_rule_inet_token_present);
  ATF_ADD_TEST_CASE(tcs, snat_rule_excludes_intra_pool_traffic);
  ATF_ADD_TEST_CASE(tcs, snat_rule_uses_iface_token);
  ATF_ADD_TEST_CASE(tcs, anchor_line_has_trailing_newline);
  ATF_ADD_TEST_CASE(tcs, anchor_line_starts_with_rule);
  ATF_ADD_TEST_CASE(tcs, proto_typical);
  ATF_ADD_TEST_CASE(tcs, proto_invalid);
  ATF_ADD_TEST_CASE(tcs, port_typical);
  ATF_ADD_TEST_CASE(tcs, port_invalid);
  ATF_ADD_TEST_CASE(tcs, rdr_single_port_shape);
  ATF_ADD_TEST_CASE(tcs, rdr_range_both_sides);
  ATF_ADD_TEST_CASE(tcs, rdr_range_host_single_jail);
  ATF_ADD_TEST_CASE(tcs, rdr_uses_iface_token_for_dest);
  ATF_ADD_TEST_CASE(tcs, rdr_inet_qualifier_present);
  ATF_ADD_TEST_CASE(tcs, rdr_anchor_line_has_trailing_newline);
  ATF_ADD_TEST_CASE(tcs, ipfw_ids_deterministic_per_jid);
  ATF_ADD_TEST_CASE(tcs, ipfw_ids_in_reserved_ranges);
  ATF_ADD_TEST_CASE(tcs, ipfw_validate_id_range);
  ATF_ADD_TEST_CASE(tcs, ipfw_nat_config_argv_shape);
  ATF_ADD_TEST_CASE(tcs, ipfw_nat_rule_argv_shape);
  ATF_ADD_TEST_CASE(tcs, ipfw_delete_argvs);
  ATF_ADD_TEST_CASE(tcs, ipfw_nat_with_no_redirs_equivalent_to_basic);
  ATF_ADD_TEST_CASE(tcs, ipfw_nat_redir_single_port);
  ATF_ADD_TEST_CASE(tcs, ipfw_nat_redir_range);
  ATF_ADD_TEST_CASE(tcs, ipfw_nat_redir_asymmetric_range);
  ATF_ADD_TEST_CASE(tcs, ipfw_nat_redir_multiple);
  ATF_ADD_TEST_CASE(tcs, orphan_rules_picks_non_running);
  ATF_ADD_TEST_CASE(tcs, orphan_rules_skips_out_of_range);
  ATF_ADD_TEST_CASE(tcs, orphan_rules_handles_crlf_blanks);
  ATF_ADD_TEST_CASE(tcs, orphan_throttle_pair_jid_division);
  ATF_ADD_TEST_CASE(tcs, orphan_nat_ids_basic);
  ATF_ADD_TEST_CASE(tcs, orphan_nat_ids_skips_non_nat_lines);
  ATF_ADD_TEST_CASE(tcs, loopback_rule_id_distinct_from_main);
  ATF_ADD_TEST_CASE(tcs, loopback_argv_shape);
  ATF_ADD_TEST_CASE(tcs, orphan_scan_recognises_loopback_range);
}
