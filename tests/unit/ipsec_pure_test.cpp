// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ipsec_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using IpsecPure::ConnSpec;
using IpsecPure::validateHost;
using IpsecPure::validateSubnet;
using IpsecPure::validateProposal;
using IpsecPure::validateAuto;
using IpsecPure::validateAuthby;
using IpsecPure::validateConnName;
using IpsecPure::validateConfig;
using IpsecPure::renderConf;

// --- validateHost ---

ATF_TEST_CASE_WITHOUT_HEAD(host_v4_accepted);
ATF_TEST_CASE_BODY(host_v4_accepted) {
  ATF_REQUIRE_EQ(validateHost("203.0.113.5"),  std::string());
  ATF_REQUIRE_EQ(validateHost("10.0.0.1"),     std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(host_v6_and_bracketed_accepted);
ATF_TEST_CASE_BODY(host_v6_and_bracketed_accepted) {
  ATF_REQUIRE_EQ(validateHost("fd00::1"),       std::string());
  ATF_REQUIRE_EQ(validateHost("[2001:db8::1]"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(host_hostname_and_any_accepted);
ATF_TEST_CASE_BODY(host_hostname_and_any_accepted) {
  ATF_REQUIRE_EQ(validateHost("vpn.example.com"), std::string());
  ATF_REQUIRE_EQ(validateHost("%any"),            std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(host_invalid_rejected);
ATF_TEST_CASE_BODY(host_invalid_rejected) {
  ATF_REQUIRE(!validateHost("").empty());
  ATF_REQUIRE(!validateHost("256.0.0.1").empty());
  ATF_REQUIRE(!validateHost("under_score").empty());
  ATF_REQUIRE(!validateHost("[zzz::1]").empty());
}

// --- validateSubnet ---

ATF_TEST_CASE_WITHOUT_HEAD(subnet_v4_typical_accepted);
ATF_TEST_CASE_BODY(subnet_v4_typical_accepted) {
  ATF_REQUIRE_EQ(validateSubnet("10.0.1.0/24"),   std::string());
  ATF_REQUIRE_EQ(validateSubnet("0.0.0.0/0"),     std::string());
  ATF_REQUIRE_EQ(validateSubnet("192.168.1.5/32"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(subnet_v6_accepted);
ATF_TEST_CASE_BODY(subnet_v6_accepted) {
  ATF_REQUIRE_EQ(validateSubnet("2001:db8::/32"), std::string());
  ATF_REQUIRE_EQ(validateSubnet("::/0"),          std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(subnet_invalid_rejected);
ATF_TEST_CASE_BODY(subnet_invalid_rejected) {
  ATF_REQUIRE(!validateSubnet("").empty());
  ATF_REQUIRE(!validateSubnet("10.0.0.1").empty());     // missing prefix
  ATF_REQUIRE(!validateSubnet("10.0.0.1/33").empty());  // v4 prefix too high
  ATF_REQUIRE(!validateSubnet("fd00::1/129").empty());  // v6 prefix too high
}

// --- validateProposal ---

ATF_TEST_CASE_WITHOUT_HEAD(proposal_typical_accepted);
ATF_TEST_CASE_BODY(proposal_typical_accepted) {
  ATF_REQUIRE_EQ(validateProposal("aes256-sha256-modp2048"),       std::string());
  ATF_REQUIRE_EQ(validateProposal("aes128gcm16-prfsha256-x25519"), std::string());
  ATF_REQUIRE_EQ(validateProposal("aes_256-sha2_256"),             std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(proposal_invalid_rejected);
ATF_TEST_CASE_BODY(proposal_invalid_rejected) {
  ATF_REQUIRE(!validateProposal("").empty());
  ATF_REQUIRE(!validateProposal("aes256;rm").empty());
  ATF_REQUIRE(!validateProposal("aes 256").empty());
}

// --- validateAuto / validateAuthby ---

ATF_TEST_CASE_WITHOUT_HEAD(auto_keywords);
ATF_TEST_CASE_BODY(auto_keywords) {
  for (auto &k : {"ignore", "add", "route", "start"})
    ATF_REQUIRE_EQ(validateAuto(k), std::string());
  ATF_REQUIRE(!validateAuto("nope").empty());
  ATF_REQUIRE(!validateAuto("").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(authby_keywords);
ATF_TEST_CASE_BODY(authby_keywords) {
  for (auto &k : {"psk", "pubkey", "rsasig", "ecdsasig", "never"})
    ATF_REQUIRE_EQ(validateAuthby(k), std::string());
  ATF_REQUIRE(!validateAuthby("password").empty());
  ATF_REQUIRE(!validateAuthby("").empty());
}

// --- validateConnName ---

ATF_TEST_CASE_WITHOUT_HEAD(conn_name_typical_accepted);
ATF_TEST_CASE_BODY(conn_name_typical_accepted) {
  ATF_REQUIRE_EQ(validateConnName("site-to-site"),  std::string());
  ATF_REQUIRE_EQ(validateConnName("vpn_a"),         std::string());
  ATF_REQUIRE_EQ(validateConnName("link.dc1.dc2"),  std::string());
  ATF_REQUIRE_EQ(validateConnName(std::string(32, 'a')), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(conn_name_invalid_rejected);
ATF_TEST_CASE_BODY(conn_name_invalid_rejected) {
  ATF_REQUIRE(!validateConnName("").empty());
  ATF_REQUIRE(!validateConnName(std::string(33, 'a')).empty());
  ATF_REQUIRE(!validateConnName("%default").empty());
  ATF_REQUIRE(!validateConnName("foo bar").empty());
  ATF_REQUIRE(!validateConnName("foo;rm").empty());
  ATF_REQUIRE(!validateConnName("foo/bar").empty());
}

// --- validateConfig (integration) ---

static ConnSpec goodConn() {
  ConnSpec c;
  c.name = "site-to-site";
  c.left = "203.0.113.5";
  c.leftSubnet = {"10.0.1.0/24"};
  c.right = "198.51.100.7";
  c.rightSubnet = {"10.0.2.0/24"};
  c.keyExchange = "ikev2";
  c.authBy = "psk";
  c.autoStart = "start";
  return c;
}

ATF_TEST_CASE_WITHOUT_HEAD(config_minimal_valid);
ATF_TEST_CASE_BODY(config_minimal_valid) {
  ATF_REQUIRE_EQ(validateConfig({goodConn()}), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(config_no_conns_rejected);
ATF_TEST_CASE_BODY(config_no_conns_rejected) {
  ATF_REQUIRE(!validateConfig({}).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(config_keyexchange_invalid_rejected);
ATF_TEST_CASE_BODY(config_keyexchange_invalid_rejected) {
  auto c = goodConn();
  c.keyExchange = "ikev3";
  auto err = validateConfig({c});
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err.find("keyexchange") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(config_conn_index_in_error);
ATF_TEST_CASE_BODY(config_conn_index_in_error) {
  std::vector<ConnSpec> conns = {goodConn(), goodConn(), goodConn()};
  conns[1].right = "256.0.0.1";   // bad IPv4
  auto err = validateConfig(conns);
  ATF_REQUIRE(err.find("conn #2") != std::string::npos);
}

// --- renderConf ---

ATF_TEST_CASE_WITHOUT_HEAD(render_emits_setup_and_conn);
ATF_TEST_CASE_BODY(render_emits_setup_and_conn) {
  auto out = renderConf({goodConn()});
  ATF_REQUIRE(out.find("config setup") != std::string::npos);
  ATF_REQUIRE(out.find("conn site-to-site") != std::string::npos);
  ATF_REQUIRE(out.find("    left=203.0.113.5")        != std::string::npos);
  ATF_REQUIRE(out.find("    leftsubnet=10.0.1.0/24")   != std::string::npos);
  ATF_REQUIRE(out.find("    right=198.51.100.7")       != std::string::npos);
  ATF_REQUIRE(out.find("    rightsubnet=10.0.2.0/24")  != std::string::npos);
  ATF_REQUIRE(out.find("    keyexchange=ikev2")        != std::string::npos);
  ATF_REQUIRE(out.find("    authby=psk")               != std::string::npos);
  ATF_REQUIRE(out.find("    auto=start")               != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_csv_joins_subnets);
ATF_TEST_CASE_BODY(render_csv_joins_subnets) {
  auto c = goodConn();
  c.leftSubnet = {"10.0.1.0/24", "10.0.3.0/24"};
  auto out = renderConf({c});
  ATF_REQUIRE(out.find("leftsubnet=10.0.1.0/24,10.0.3.0/24") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_omits_optional_fields_when_empty);
ATF_TEST_CASE_BODY(render_omits_optional_fields_when_empty) {
  auto c = goodConn();
  c.ike.clear();
  c.esp.clear();
  auto out = renderConf({c});
  ATF_REQUIRE(out.find("\n    ike=") == std::string::npos);
  ATF_REQUIRE(out.find("\n    esp=") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_emits_optional_ike_esp);
ATF_TEST_CASE_BODY(render_emits_optional_ike_esp) {
  auto c = goodConn();
  c.ike = "aes256-sha256-modp2048";
  c.esp = "aes256-sha256";
  auto out = renderConf({c});
  ATF_REQUIRE(out.find("    ike=aes256-sha256-modp2048") != std::string::npos);
  ATF_REQUIRE(out.find("    esp=aes256-sha256")           != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_includes_description_comment);
ATF_TEST_CASE_BODY(render_includes_description_comment) {
  auto c = goodConn();
  c.description = "DC1 ↔ DC2";
  auto out = renderConf({c});
  ATF_REQUIRE(out.find("# DC1 ↔ DC2") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_multiple_conns_separated);
ATF_TEST_CASE_BODY(render_multiple_conns_separated) {
  auto a = goodConn(); a.name = "tun-a"; a.description = "first";
  auto b = goodConn(); b.name = "tun-b"; b.description = "second";
  auto out = renderConf({a, b});
  ATF_REQUIRE(out.find("conn tun-a") != std::string::npos);
  ATF_REQUIRE(out.find("conn tun-b") != std::string::npos);
  ATF_REQUIRE(out.find("# first")    < out.find("# second"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, host_v4_accepted);
  ATF_ADD_TEST_CASE(tcs, host_v6_and_bracketed_accepted);
  ATF_ADD_TEST_CASE(tcs, host_hostname_and_any_accepted);
  ATF_ADD_TEST_CASE(tcs, host_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, subnet_v4_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, subnet_v6_accepted);
  ATF_ADD_TEST_CASE(tcs, subnet_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, proposal_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, proposal_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, auto_keywords);
  ATF_ADD_TEST_CASE(tcs, authby_keywords);
  ATF_ADD_TEST_CASE(tcs, conn_name_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, conn_name_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, config_minimal_valid);
  ATF_ADD_TEST_CASE(tcs, config_no_conns_rejected);
  ATF_ADD_TEST_CASE(tcs, config_keyexchange_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, config_conn_index_in_error);
  ATF_ADD_TEST_CASE(tcs, render_emits_setup_and_conn);
  ATF_ADD_TEST_CASE(tcs, render_csv_joins_subnets);
  ATF_ADD_TEST_CASE(tcs, render_omits_optional_fields_when_empty);
  ATF_ADD_TEST_CASE(tcs, render_emits_optional_ike_esp);
  ATF_ADD_TEST_CASE(tcs, render_includes_description_comment);
  ATF_ADD_TEST_CASE(tcs, render_multiple_conns_separated);
}
