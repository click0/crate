// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "iface_owner_registry_pure.h"

#include <atf-c++.hpp>

#include <set>

using IfaceOwnerRegistryPure::EntryMap;
using IfaceOwnerRegistryPure::hostHalf;
using IfaceOwnerRegistryPure::isEpairName;
using IfaceOwnerRegistryPure::parse;
using IfaceOwnerRegistryPure::peerHalf;
using IfaceOwnerRegistryPure::reconcile;
using IfaceOwnerRegistryPure::serialize;

ATF_TEST_CASE_WITHOUT_HEAD(epair_name_shape);
ATF_TEST_CASE_BODY(epair_name_shape) {
  ATF_REQUIRE(isEpairName("epair0a"));
  ATF_REQUIRE(isEpairName("epair0b"));
  ATF_REQUIRE(isEpairName("epair123a"));
  ATF_REQUIRE(!isEpairName("epair"));        // no unit, no half
  ATF_REQUIRE(!isEpairName("epair0"));       // no half
  ATF_REQUIRE(!isEpairName("epaira"));       // no unit
  ATF_REQUIRE(!isEpairName("epair0c"));      // not a/b
  ATF_REQUIRE(!isEpairName("epair0ab"));     // trailing junk
  ATF_REQUIRE(!isEpairName("em0"));          // host NIC
  ATF_REQUIRE(!isEpairName("bridge0"));
  ATF_REQUIRE(!isEpairName("vlan0"));
  ATF_REQUIRE(!isEpairName(""));
  ATF_REQUIRE(!isEpairName("xepair0a"));

  ATF_REQUIRE_EQ(peerHalf("epair3a"), std::string("epair3b"));
  ATF_REQUIRE_EQ(peerHalf("epair3b"), std::string("epair3a"));
  ATF_REQUIRE_EQ(peerHalf("em0"), std::string());
  ATF_REQUIRE_EQ(hostHalf("epair3b"), std::string("epair3a"));
  ATF_REQUIRE_EQ(hostHalf("epair3a"), std::string("epair3a"));
  ATF_REQUIRE_EQ(hostHalf("bridge0"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(serialize_parse_round_trip);
ATF_TEST_CASE_BODY(serialize_parse_round_trip) {
  EntryMap m;
  m["epair7a"] = 1000;
  m["epair7b"] = 1000;
  m["epair12a"] = 1001;
  std::string s = serialize(m);
  // sorted by name (std::map), one line each, trailing newline
  ATF_REQUIRE_EQ(s, std::string("epair12a\t1001\nepair7a\t1000\nepair7b\t1000\n"));
  EntryMap back; std::string err;
  ATF_REQUIRE(parse(s, back, err));
  ATF_REQUIRE(back == m);
  ATF_REQUIRE_EQ(serialize(EntryMap{}), std::string());
  ATF_REQUIRE(parse("", back, err) && back.empty());
  // comments and blank lines are fine
  ATF_REQUIRE(parse("# header\n\nepair1a\t5\n", back, err));
  ATF_REQUIRE_EQ(back.at("epair1a"), 5u);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_fails_closed);
ATF_TEST_CASE_BODY(parse_fails_closed) {
  EntryMap out; std::string err;
  // not an epair half
  ATF_REQUIRE(!parse("em0\t1000\n", out, err));
  ATF_REQUIRE(out.empty() && err.find("epair") != std::string::npos);
  // wrong column count
  ATF_REQUIRE(!parse("epair0a\t1000\textra\n", out, err));
  ATF_REQUIRE(!parse("epair0a 1000\n", out, err));
  ATF_REQUIRE(!parse("\t1000\n", out, err));
  // uid garbage / overflow
  ATF_REQUIRE(!parse("epair0a\tabc\n", out, err));
  ATF_REQUIRE(!parse("epair0a\t99999999999\n", out, err));
  // duplicate
  ATF_REQUIRE(!parse("epair0a\t1\nepair0a\t2\n", out, err));
  ATF_REQUIRE(err.find("duplicate") != std::string::npos);
  // a good line before the bad one does not survive (whole parse fails)
  ATF_REQUIRE(!parse("epair0a\t1\nbogus\n", out, err));
  ATF_REQUIRE(out.empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(reconcile_probes_host_half_and_drops_pairs);
ATF_TEST_CASE_BODY(reconcile_probes_host_half_and_drops_pairs) {
  EntryMap m;
  m["epair1a"] = 1000; m["epair1b"] = 1000;    // alive
  m["epair2a"] = 1001; m["epair2b"] = 1001;    // gone
  m["epair3b"] = 1002;                         // only the b half recorded, pair gone
  std::set<std::string> probed;
  auto live = [&](const std::string &n) { probed.insert(n); return n == "epair1a"; };
  size_t dropped = reconcile(m, live);
  ATF_REQUIRE_EQ(dropped, 3u);
  ATF_REQUIRE_EQ(m.size(), 2u);
  ATF_REQUIRE(m.count("epair1a") && m.count("epair1b"));
  // the b halves were probed through their a half — never asked about
  // a name the host cannot see
  ATF_REQUIRE(probed.count("epair3a") && !probed.count("epair3b"));
  ATF_REQUIRE(!probed.count("epair1b"));
  // no probe -> nothing dropped
  EntryMap m2 = m;
  ATF_REQUIRE_EQ(reconcile(m2, nullptr), 0u);
  ATF_REQUIRE(m2 == m);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, epair_name_shape);
  ATF_ADD_TEST_CASE(tcs, serialize_parse_round_trip);
  ATF_ADD_TEST_CASE(tcs, parse_fails_closed);
  ATF_ADD_TEST_CASE(tcs, reconcile_probes_host_half_and_drops_pairs);
}
