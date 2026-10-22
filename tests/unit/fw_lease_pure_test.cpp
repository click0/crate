// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "fw_lease_pure.h"
#include "fw_lease_registry.h"

#include <atf-c++.hpp>

#include <cstdio>
#include <map>
#include <string>

using namespace FwLeasePure;

ATF_TEST_CASE_WITHOUT_HEAD(acquire_allocates_lowest_slot_and_counts);
ATF_TEST_CASE_BODY(acquire_allocates_lowest_slot_and_counts) {
  State s;
  Entry e; Transition t; std::string err;
  ATF_REQUIRE(acquire(s, 10, true, true, false, e, t, err));
  ATF_REQUIRE_EQ(e.slot, 0);
  ATF_REQUIRE(t.first4); ATF_REQUIRE(!t.first6); ATF_REQUIRE(!t.last4);
  ATF_REQUIRE(acquire(s, 11, true, true, true, e, t, err));
  ATF_REQUIRE_EQ(e.slot, 1);
  ATF_REQUIRE(!t.first4); ATF_REQUIRE(t.first6);
  // bridge mode: forwarding only, no slot
  ATF_REQUIRE(acquire(s, 12, false, true, false, e, t, err));
  ATF_REQUIRE_EQ(e.slot, -1);
  auto c = counts(s);
  ATF_REQUIRE_EQ(c.fwd4, 3u); ATF_REQUIRE_EQ(c.fwd6, 1u);
  // re-acquire is idempotent: same slot, extra reference added
  ATF_REQUIRE(acquire(s, 10, true, true, true, e, t, err));
  ATF_REQUIRE_EQ(e.slot, 0);
  ATF_REQUIRE_EQ(counts(s).fwd6, 2u);
  ATF_REQUIRE_EQ(s.leases.size(), 3u);
  // slot reuse after release: 11 goes, next slot request gets 1
  bool found = false;
  t = release(s, 11, found);
  ATF_REQUIRE(found); ATF_REQUIRE(!t.last4); ATF_REQUIRE(!t.last6);
  ATF_REQUIRE(acquire(s, 13, true, false, false, e, t, err));
  ATF_REQUIRE_EQ(e.slot, 1);
}

ATF_TEST_CASE_WITHOUT_HEAD(release_reports_last_and_unknown);
ATF_TEST_CASE_BODY(release_reports_last_and_unknown) {
  State s;
  Entry e; Transition t; std::string err;
  ATF_REQUIRE(acquire(s, 5, true, true, true, e, t, err));
  bool found = true;
  t = release(s, 999, found);
  ATF_REQUIRE(!found); ATF_REQUIRE(!t.last4);
  t = release(s, 5, found);
  ATF_REQUIRE(found); ATF_REQUIRE(t.last4); ATF_REQUIRE(t.last6);
  ATF_REQUIRE(s.leases.empty());
  ATF_REQUIRE_EQ(lowestFreeSlot(s), 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(slot_exhaustion);
ATF_TEST_CASE_BODY(slot_exhaustion) {
  State s;
  Entry e; Transition t; std::string err;
  for (int i = 0; i < kMaxSlots; i++)
    ATF_REQUIRE(acquire(s, (unsigned)(i + 1), true, false, false, e, t, err));
  ATF_REQUIRE(!acquire(s, 60000, true, false, false, e, t, err));
  ATF_REQUIRE(err.find("no free firewall slot") != std::string::npos);
  // a forwarding-only lease still works when slots are gone
  ATF_REQUIRE(acquire(s, 60000, false, true, false, e, t, err));
  ATF_REQUIRE_EQ(e.slot, -1);
}

ATF_TEST_CASE_WITHOUT_HEAD(reconcile_drops_dead_and_reports_last);
ATF_TEST_CASE_BODY(reconcile_drops_dead_and_reports_last) {
  State s;
  Entry e; Transition t; std::string err;
  acquire(s, 1, true, true, false, e, t, err);
  acquire(s, 2, true, true, true, e, t, err);
  acquire(s, 3, false, false, true, e, t, err);
  size_t dropped = 0;
  t = reconcile(s, [](unsigned jid) { return jid == 2; }, dropped);
  ATF_REQUIRE_EQ(dropped, 2u);
  ATF_REQUIRE(!t.last4); ATF_REQUIRE(!t.last6);   // jid 2 still holds both
  t = reconcile(s, [](unsigned) { return false; }, dropped);
  ATF_REQUIRE_EQ(dropped, 1u);
  ATF_REQUIRE(t.last4); ATF_REQUIRE(t.last6);
}

ATF_TEST_CASE_WITHOUT_HEAD(serialize_parse_round_trip_and_rejects);
ATF_TEST_CASE_BODY(serialize_parse_round_trip_and_rejects) {
  State s;
  Entry e; Transition t; std::string err;
  acquire(s, 7, true, true, false, e, t, err);
  acquire(s, 9, false, true, true, e, t, err);
  s.orig4 = 0; s.orig6 = -1;
  auto text = serialize(s);
  State back;
  ATF_REQUIRE(parse(text, back, err));
  ATF_REQUIRE_EQ(back.orig4, 0); ATF_REQUIRE_EQ(back.orig6, -1);
  ATF_REQUIRE_EQ(back.leases.size(), 2u);
  ATF_REQUIRE_EQ(back.leases[7].slot, 0);
  ATF_REQUIRE(back.leases[7].fwd4); ATF_REQUIRE(!back.leases[7].fwd6);
  ATF_REQUIRE_EQ(back.leases[9].slot, -1);
  ATF_REQUIRE(back.leases[9].fwd6);
  // empty / comments only
  ATF_REQUIRE(parse("", back, err)); ATF_REQUIRE(back.leases.empty());
  ATF_REQUIRE(parse("# just a comment\n", back, err));
  // rejects
  ATF_REQUIRE(!parse("7\t0\t1\n", back, err));                 // 3 fields
  ATF_REQUIRE(!parse("0\t0\t1\t0\n", back, err));              // jid 0
  ATF_REQUIRE(!parse("7\t1500\t1\t0\n", back, err));           // slot >= kMaxSlots
  ATF_REQUIRE(!parse("7\t0\t2\t0\n", back, err));              // bool out of range
  ATF_REQUIRE(!parse("7\t0\t1\t0\n7\t1\t1\t0\n", back, err));  // duplicate jid
  ATF_REQUIRE(!parse("7\t0\t1\t0\n8\t0\t1\t0\n", back, err));  // slot held twice
  ATF_REQUIRE(err.find("slot 0") != std::string::npos);
  ATF_REQUIRE(!parse("orig4\t5\torig6\t0\n", back, err));      // orig out of range
}

// Registry with fake sysctls: first user switches forwarding on only
// when it was 0, last user restores only what was changed, and the
// state survives a reload from disk.
ATF_TEST_CASE_WITHOUT_HEAD(registry_flips_sysctls_and_persists);
ATF_TEST_CASE_BODY(registry_flips_sysctls_and_persists) {
  std::map<std::string, int> sysctl = {{"net.inet.ip.forwarding", 0},
                                       {"net.inet6.ip6.forwarding", 1}};
  FwLeaseRegistry::SysctlIo io;
  io.get = [&sysctl](const char *n) { return sysctl.at(n); };
  io.set = [&sysctl](const char *n, int v) { sysctl.at(n) = v; };
  const char *path = "fw_leases.tsv";
  std::remove(path);
  {
    FwLeaseRegistry reg(path, io);
    FwLeaseRegistry::Result r;
    ATF_REQUIRE_EQ(reg.acquire(41, true, true, true, r), std::string());
    ATF_REQUIRE_EQ(r.slot, 0);
    ATF_REQUIRE_EQ(r.fwd4Users, 1u); ATF_REQUIRE_EQ(r.fwd6Users, 1u);
    ATF_REQUIRE_EQ(sysctl["net.inet.ip.forwarding"], 1);     // switched on
    ATF_REQUIRE_EQ(sysctl["net.inet6.ip6.forwarding"], 1);   // was already on
    ATF_REQUIRE_EQ(reg.acquire(42, false, true, false, r), std::string());
    ATF_REQUIRE_EQ(r.slot, -1);
    ATF_REQUIRE_EQ(r.fwd4Users, 2u);
  }
  // daemon restart: state reloaded, orig4 remembered as 0
  {
    FwLeaseRegistry reg(path, io);
    ATF_REQUIRE_EQ(reg.size(), 2u);
    auto r = reg.release(41);
    ATF_REQUIRE(r.released);
    ATF_REQUIRE_EQ(r.fwd4Users, 1u); ATF_REQUIRE_EQ(r.fwd6Users, 0u);
    ATF_REQUIRE_EQ(sysctl["net.inet6.ip6.forwarding"], 1);   // not ours to restore
    ATF_REQUIRE_EQ(sysctl["net.inet.ip.forwarding"], 1);     // 42 still holds it
    r = reg.release(42);
    ATF_REQUIRE(r.released);
    ATF_REQUIRE_EQ(r.fwd4Users, 0u);
    ATF_REQUIRE_EQ(sysctl["net.inet.ip.forwarding"], 0);     // restored
    r = reg.release(42);
    ATF_REQUIRE(!r.released);
    ATF_REQUIRE_EQ(reg.size(), 0u);
  }
  // reconcile restores too: lease taken, jail "dies", probe drops it
  {
    FwLeaseRegistry reg(path, io);
    FwLeaseRegistry::Result r;
    ATF_REQUIRE_EQ(reg.acquire(50, true, true, false, r), std::string());
    ATF_REQUIRE_EQ(sysctl["net.inet.ip.forwarding"], 1);
    reg.setLiveProbe([](unsigned) { return false; });
    ATF_REQUIRE_EQ(reg.reconcile(), 1u);
    ATF_REQUIRE_EQ(sysctl["net.inet.ip.forwarding"], 0);
  }
  // a malformed file is an error the operator sees
  {
    FILE *f = std::fopen(path, "w");
    ATF_REQUIRE(f != nullptr);
    std::fputs("garbage line\n", f);
    std::fclose(f);
    bool threw = false;
    try { FwLeaseRegistry reg(path, io); } catch (const std::exception &) { threw = true; }
    ATF_REQUIRE(threw);
  }
  std::remove(path);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, acquire_allocates_lowest_slot_and_counts);
  ATF_ADD_TEST_CASE(tcs, release_reports_last_and_unknown);
  ATF_ADD_TEST_CASE(tcs, slot_exhaustion);
  ATF_ADD_TEST_CASE(tcs, reconcile_drops_dead_and_reports_last);
  ATF_ADD_TEST_CASE(tcs, serialize_parse_round_trip_and_rejects);
  ATF_ADD_TEST_CASE(tcs, registry_flips_sysctls_and_persists);
}
