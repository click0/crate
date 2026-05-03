// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "wireguard_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using WireguardPure::InterfaceSpec;
using WireguardPure::PeerSpec;
using WireguardPure::validateKey;
using WireguardPure::validatePort;
using WireguardPure::validateCidr;
using WireguardPure::validateEndpoint;
using WireguardPure::validateConfig;
using WireguardPure::renderConf;

// 32 zero bytes encoded as base64 — a syntactically valid placeholder.
static const std::string ZERO_KEY =
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

// --- validateKey ---

ATF_TEST_CASE_WITHOUT_HEAD(key_zero_bytes_accepted);
ATF_TEST_CASE_BODY(key_zero_bytes_accepted) {
  ATF_REQUIRE_EQ(validateKey(ZERO_KEY), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(key_wrong_length_rejected);
ATF_TEST_CASE_BODY(key_wrong_length_rejected) {
  ATF_REQUIRE(!validateKey("").empty());
  ATF_REQUIRE(!validateKey("AAAA").empty());
  ATF_REQUIRE(!validateKey(ZERO_KEY + "A").empty());      // 45 chars
  ATF_REQUIRE(!validateKey(ZERO_KEY.substr(1)).empty()); // 43 chars
}

ATF_TEST_CASE_WITHOUT_HEAD(key_missing_padding_rejected);
ATF_TEST_CASE_BODY(key_missing_padding_rejected) {
  // 44 chars but no trailing '='
  ATF_REQUIRE(!validateKey(std::string(44, 'A')).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(key_invalid_base64_char_rejected);
ATF_TEST_CASE_BODY(key_invalid_base64_char_rejected) {
  std::string bad = ZERO_KEY;
  bad[10] = '*';
  ATF_REQUIRE(!validateKey(bad).empty());
  bad = ZERO_KEY;
  bad[5] = '\n';
  ATF_REQUIRE(!validateKey(bad).empty());
}

// --- validatePort ---

ATF_TEST_CASE_WITHOUT_HEAD(port_typical_range_accepted);
ATF_TEST_CASE_BODY(port_typical_range_accepted) {
  ATF_REQUIRE_EQ(validatePort("1"),     std::string());
  ATF_REQUIRE_EQ(validatePort("51820"), std::string());
  ATF_REQUIRE_EQ(validatePort("65535"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(port_edge_cases_rejected);
ATF_TEST_CASE_BODY(port_edge_cases_rejected) {
  ATF_REQUIRE(!validatePort("").empty());
  ATF_REQUIRE(!validatePort("0").empty());
  ATF_REQUIRE(!validatePort("65536").empty());
  ATF_REQUIRE(!validatePort("99999").empty());
  ATF_REQUIRE(!validatePort("abc").empty());
  ATF_REQUIRE(!validatePort("-5").empty());
}

// --- validateCidr ---

ATF_TEST_CASE_WITHOUT_HEAD(cidr_v4_typical_accepted);
ATF_TEST_CASE_BODY(cidr_v4_typical_accepted) {
  ATF_REQUIRE_EQ(validateCidr("10.0.0.1/24"),     std::string());
  ATF_REQUIRE_EQ(validateCidr("0.0.0.0/0"),       std::string());
  ATF_REQUIRE_EQ(validateCidr("192.168.1.5/32"),  std::string());
  ATF_REQUIRE_EQ(validateCidr("255.255.255.255/32"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(cidr_v4_invalid_rejected);
ATF_TEST_CASE_BODY(cidr_v4_invalid_rejected) {
  ATF_REQUIRE(!validateCidr("").empty());
  ATF_REQUIRE(!validateCidr("10.0.0.1").empty());      // missing prefix
  ATF_REQUIRE(!validateCidr("10.0.0/24").empty());     // too few octets
  ATF_REQUIRE(!validateCidr("10.0.0.256/24").empty()); // octet > 255
  ATF_REQUIRE(!validateCidr("10.0.0.1/33").empty());   // prefix > 32 for v4
}

ATF_TEST_CASE_WITHOUT_HEAD(cidr_v6_typical_accepted);
ATF_TEST_CASE_BODY(cidr_v6_typical_accepted) {
  ATF_REQUIRE_EQ(validateCidr("fd00::1/128"),    std::string());
  ATF_REQUIRE_EQ(validateCidr("::/0"),           std::string());
  ATF_REQUIRE_EQ(validateCidr("2001:db8::/32"),  std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(cidr_v6_invalid_rejected);
ATF_TEST_CASE_BODY(cidr_v6_invalid_rejected) {
  // Two `::` shorthand uses are illegal.
  ATF_REQUIRE(!validateCidr("fd00::1::2/128").empty());
  ATF_REQUIRE(!validateCidr("fd00::1/129").empty()); // prefix > 128
  ATF_REQUIRE(!validateCidr("zzz::1/64").empty());   // non-hex
}

// --- validateEndpoint ---

ATF_TEST_CASE_WITHOUT_HEAD(endpoint_v4_accepted);
ATF_TEST_CASE_BODY(endpoint_v4_accepted) {
  ATF_REQUIRE_EQ(validateEndpoint("203.0.113.5:51820"), std::string());
  ATF_REQUIRE_EQ(validateEndpoint("1.1.1.1:53"),        std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(endpoint_v6_bracketed_accepted);
ATF_TEST_CASE_BODY(endpoint_v6_bracketed_accepted) {
  ATF_REQUIRE_EQ(validateEndpoint("[::1]:51820"),         std::string());
  ATF_REQUIRE_EQ(validateEndpoint("[2001:db8::1]:51820"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(endpoint_hostname_accepted);
ATF_TEST_CASE_BODY(endpoint_hostname_accepted) {
  ATF_REQUIRE_EQ(validateEndpoint("vpn.example.com:51820"), std::string());
  ATF_REQUIRE_EQ(validateEndpoint("a-b-c.local:9999"),       std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(endpoint_malformed_rejected);
ATF_TEST_CASE_BODY(endpoint_malformed_rejected) {
  ATF_REQUIRE(!validateEndpoint("").empty());
  ATF_REQUIRE(!validateEndpoint("host").empty());        // no port
  ATF_REQUIRE(!validateEndpoint("[::1]").empty());        // no port
  ATF_REQUIRE(!validateEndpoint("[::1:51820").empty());   // missing ']'
  ATF_REQUIRE(!validateEndpoint("host:99999").empty());   // port out of range
  ATF_REQUIRE(!validateEndpoint("under_score:80").empty()); // illegal hostname char
}

// --- validateConfig (integration) ---

static InterfaceSpec goodIface() {
  InterfaceSpec i;
  i.privateKey = ZERO_KEY;
  i.addresses = {"10.0.0.1/24"};
  i.listenPort = "51820";
  return i;
}

static PeerSpec goodPeer() {
  PeerSpec p;
  p.publicKey = ZERO_KEY;
  p.allowedIps = {"10.0.0.2/32"};
  return p;
}

ATF_TEST_CASE_WITHOUT_HEAD(config_minimal_valid);
ATF_TEST_CASE_BODY(config_minimal_valid) {
  ATF_REQUIRE_EQ(validateConfig(goodIface(), {goodPeer()}), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(config_no_peers_rejected);
ATF_TEST_CASE_BODY(config_no_peers_rejected) {
  auto err = validateConfig(goodIface(), {});
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err.find("[Peer]") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(config_no_addresses_rejected);
ATF_TEST_CASE_BODY(config_no_addresses_rejected) {
  auto i = goodIface();
  i.addresses.clear();
  ATF_REQUIRE(!validateConfig(i, {goodPeer()}).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(config_peer_index_in_error);
ATF_TEST_CASE_BODY(config_peer_index_in_error) {
  std::vector<PeerSpec> peers = {goodPeer(), goodPeer(), goodPeer()};
  peers[1].publicKey = "shortkey";
  auto err = validateConfig(goodIface(), peers);
  ATF_REQUIRE(err.find("peer #2") != std::string::npos);
}

// --- renderConf ---

ATF_TEST_CASE_WITHOUT_HEAD(render_emits_interface_section);
ATF_TEST_CASE_BODY(render_emits_interface_section) {
  auto out = renderConf(goodIface(), {goodPeer()});
  ATF_REQUIRE(out.find("[Interface]")              != std::string::npos);
  ATF_REQUIRE(out.find("PrivateKey = " + ZERO_KEY) != std::string::npos);
  ATF_REQUIRE(out.find("Address = 10.0.0.1/24")    != std::string::npos);
  ATF_REQUIRE(out.find("ListenPort = 51820")       != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_csv_joins_addresses);
ATF_TEST_CASE_BODY(render_csv_joins_addresses) {
  auto i = goodIface();
  i.addresses = {"10.0.0.1/24", "fd00::1/64"};
  auto out = renderConf(i, {goodPeer()});
  ATF_REQUIRE(out.find("Address = 10.0.0.1/24, fd00::1/64") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_omits_optional_listenport);
ATF_TEST_CASE_BODY(render_omits_optional_listenport) {
  auto i = goodIface();
  i.listenPort.clear();
  auto out = renderConf(i, {goodPeer()});
  ATF_REQUIRE(out.find("ListenPort") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_emits_peer_section);
ATF_TEST_CASE_BODY(render_emits_peer_section) {
  auto p = goodPeer();
  p.endpoint = "203.0.113.5:51820";
  p.persistentKeepalive = "25";
  p.description = "Edge router";
  auto out = renderConf(goodIface(), {p});
  ATF_REQUIRE(out.find("# Edge router")              != std::string::npos);
  ATF_REQUIRE(out.find("[Peer]")                     != std::string::npos);
  ATF_REQUIRE(out.find("PublicKey = " + ZERO_KEY)    != std::string::npos);
  ATF_REQUIRE(out.find("AllowedIPs = 10.0.0.2/32")   != std::string::npos);
  ATF_REQUIRE(out.find("Endpoint = 203.0.113.5:51820") != std::string::npos);
  ATF_REQUIRE(out.find("PersistentKeepalive = 25")   != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_emits_preshared_when_set);
ATF_TEST_CASE_BODY(render_emits_preshared_when_set) {
  auto p = goodPeer();
  p.presharedKey = ZERO_KEY;
  auto out = renderConf(goodIface(), {p});
  ATF_REQUIRE(out.find("PresharedKey = " + ZERO_KEY) != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_omits_preshared_when_empty);
ATF_TEST_CASE_BODY(render_omits_preshared_when_empty) {
  auto out = renderConf(goodIface(), {goodPeer()});
  ATF_REQUIRE(out.find("PresharedKey") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_multiple_peers_separated);
ATF_TEST_CASE_BODY(render_multiple_peers_separated) {
  auto a = goodPeer(); a.description = "node-a";
  auto b = goodPeer(); b.description = "node-b"; b.allowedIps = {"10.0.0.3/32"};
  auto out = renderConf(goodIface(), {a, b});
  // Both [Peer] sections present.
  auto first  = out.find("[Peer]");
  auto second = out.find("[Peer]", first + 1);
  ATF_REQUIRE(first  != std::string::npos);
  ATF_REQUIRE(second != std::string::npos);
  ATF_REQUIRE(out.find("# node-a") < out.find("# node-b"));
}

ATF_TEST_CASE_WITHOUT_HEAD(render_ends_with_newline);
ATF_TEST_CASE_BODY(render_ends_with_newline) {
  auto out = renderConf(goodIface(), {goodPeer()});
  ATF_REQUIRE(!out.empty());
  ATF_REQUIRE_EQ(out.back(), '\n');
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, key_zero_bytes_accepted);
  ATF_ADD_TEST_CASE(tcs, key_wrong_length_rejected);
  ATF_ADD_TEST_CASE(tcs, key_missing_padding_rejected);
  ATF_ADD_TEST_CASE(tcs, key_invalid_base64_char_rejected);
  ATF_ADD_TEST_CASE(tcs, port_typical_range_accepted);
  ATF_ADD_TEST_CASE(tcs, port_edge_cases_rejected);
  ATF_ADD_TEST_CASE(tcs, cidr_v4_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, cidr_v4_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, cidr_v6_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, cidr_v6_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, endpoint_v4_accepted);
  ATF_ADD_TEST_CASE(tcs, endpoint_v6_bracketed_accepted);
  ATF_ADD_TEST_CASE(tcs, endpoint_hostname_accepted);
  ATF_ADD_TEST_CASE(tcs, endpoint_malformed_rejected);
  ATF_ADD_TEST_CASE(tcs, config_minimal_valid);
  ATF_ADD_TEST_CASE(tcs, config_no_peers_rejected);
  ATF_ADD_TEST_CASE(tcs, config_no_addresses_rejected);
  ATF_ADD_TEST_CASE(tcs, config_peer_index_in_error);
  ATF_ADD_TEST_CASE(tcs, render_emits_interface_section);
  ATF_ADD_TEST_CASE(tcs, render_csv_joins_addresses);
  ATF_ADD_TEST_CASE(tcs, render_omits_optional_listenport);
  ATF_ADD_TEST_CASE(tcs, render_emits_peer_section);
  ATF_ADD_TEST_CASE(tcs, render_emits_preshared_when_set);
  ATF_ADD_TEST_CASE(tcs, render_omits_preshared_when_empty);
  ATF_ADD_TEST_CASE(tcs, render_multiple_peers_separated);
  ATF_ADD_TEST_CASE(tcs, render_ends_with_newline);
}
