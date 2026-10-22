// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.57: shared firewall state for NAT / bridge mode, daemon-owned.
//
// Root-mode `crate run` coordinates two host-wide things through files in
// /var/run/crate (Ctx::FwSlots, Ctx::FwUsers): the ipfw rule-number SLOT
// of each running container and the refcount of containers that need
// net.inet.ip.forwarding / net.inet6.ip6.forwarding switched on. Neither
// is reachable from an unprivileged crate, so rootless NAT mode was
// refused (1.1.39). This module is the data model crated keeps instead:
// one lease per jid, reconciled against the live jails, with the
// original sysctl values remembered so the last user can restore them.
// Pure: no I/O, no sysctls — lib/fw_lease_registry.cpp adds both.

#pragma once

#include <cstddef>
#include <functional>
#include <map>
#include <string>

namespace FwLeasePure {

struct Entry {
  int  slot = -1;       // ipfw rule slot (>= 0) or -1 when not requested
  bool fwd4 = false;    // holds a net.inet.ip.forwarding reference
  bool fwd6 = false;    // holds a net.inet6.ip6.forwarding reference
};

struct State {
  std::map<unsigned, Entry> leases;   // jid -> lease
  // Value of the sysctl before the daemon switched it on for the first
  // user; -1 = the daemon has not touched it (nobody holds a reference,
  // or it was already 1 when the first user arrived).
  int orig4 = -1;
  int orig6 = -1;
};

struct Counts {
  unsigned fwd4 = 0;
  unsigned fwd6 = 0;
};

// What an acquire/release/reconcile changed about the shared sysctls.
struct Transition {
  bool first4 = false;   // fwd4 refcount went 0 -> 1
  bool last4  = false;   // fwd4 refcount went 1 -> 0
  bool first6 = false;
  bool last6  = false;
};

// ipfw rule layout (lib/run_net.cpp): IN rules 10000..29999 and OUT rules
// 50000..64999, `slot * slotSize(10)` inside each — 1500 slots fit the
// OUT range. The daemon refuses an acquire beyond this with a clear
// error instead of handing out a slot that would collide.
constexpr int kMaxSlots = 1500;

Counts counts(const State &s);

// Lowest slot >= 0 not held by any lease, or -1 when all are taken.
int lowestFreeSlot(const State &s, int maxSlots = kMaxSlots);

// Acquire (or re-acquire — idempotent per jid: an existing lease keeps
// its slot and gains any newly requested references). `out` is the lease
// after the call. Returns false with `err` set only when a slot was
// requested and none is free.
bool acquire(State &s, unsigned jid, bool wantSlot, bool want4, bool want6,
             Entry &out, Transition &t, std::string &err);

// Release everything held by `jid`. `found` tells whether a lease
// existed. The transition reports last4/last6 when the counts hit zero.
Transition release(State &s, unsigned jid, bool &found);

// Drop every lease whose jid `isLive` rejects. `dropped` receives the
// count; the transition reports last4/last6 when the counts hit zero.
Transition reconcile(State &s, const std::function<bool(unsigned jid)> &isLive,
                     size_t &dropped);

// On-disk form (TSV):
//   # crate fw leases v1
//   orig4\t<int>\torig6\t<int>
//   <jid>\t<slot>\t<fwd4 0|1>\t<fwd6 0|1>
std::string serialize(const State &s);
bool parse(const std::string &text, State &out, std::string &err);

}
