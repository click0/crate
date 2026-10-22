// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "fw_lease_pure.h"

#include <set>
#include <sstream>
#include <vector>

namespace FwLeasePure {

Counts counts(const State &s) {
  Counts c;
  for (auto &kv : s.leases) {
    if (kv.second.fwd4) c.fwd4++;
    if (kv.second.fwd6) c.fwd6++;
  }
  return c;
}

int lowestFreeSlot(const State &s, int maxSlots) {
  std::set<int> used;
  for (auto &kv : s.leases)
    if (kv.second.slot >= 0) used.insert(kv.second.slot);
  for (int i = 0; i < maxSlots; i++)
    if (!used.count(i)) return i;
  return -1;
}

namespace {

Transition diff(const Counts &before, const Counts &after) {
  Transition t;
  t.first4 = before.fwd4 == 0 && after.fwd4 > 0;
  t.last4  = before.fwd4 > 0 && after.fwd4 == 0;
  t.first6 = before.fwd6 == 0 && after.fwd6 > 0;
  t.last6  = before.fwd6 > 0 && after.fwd6 == 0;
  return t;
}

bool parseInt(const std::string &f, long long lo, long long hi, long long &out) {
  if (f.empty() || f.size() > 12) return false;
  size_t i = 0;
  bool neg = false;
  if (f[0] == '-') { neg = true; i = 1; if (f.size() == 1) return false; }
  long long v = 0;
  for (; i < f.size(); i++) {
    if (f[i] < '0' || f[i] > '9') return false;
    v = v * 10 + (f[i] - '0');
  }
  if (neg) v = -v;
  if (v < lo || v > hi) return false;
  out = v;
  return true;
}

std::vector<std::string> splitTabs(const std::string &line) {
  std::vector<std::string> f;
  std::string cur;
  for (char c : line) {
    if (c == '\t') { f.push_back(cur); cur.clear(); }
    else cur.push_back(c);
  }
  f.push_back(cur);
  return f;
}

} // anon

bool acquire(State &s, unsigned jid, bool wantSlot, bool want4, bool want6,
             Entry &out, Transition &t, std::string &err) {
  err.clear();
  t = Transition{};
  Counts before = counts(s);
  Entry e;
  auto it = s.leases.find(jid);
  if (it != s.leases.end()) e = it->second;
  if (wantSlot && e.slot < 0) {
    int slot = lowestFreeSlot(s);
    if (slot < 0) {
      err = "no free firewall slot (" + std::to_string(kMaxSlots) + " in use)";
      return false;
    }
    e.slot = slot;
  }
  if (want4) e.fwd4 = true;
  if (want6) e.fwd6 = true;
  s.leases[jid] = e;
  out = e;
  t = diff(before, counts(s));
  return true;
}

Transition release(State &s, unsigned jid, bool &found) {
  Counts before = counts(s);
  auto it = s.leases.find(jid);
  found = it != s.leases.end();
  if (found) s.leases.erase(it);
  return diff(before, counts(s));
}

Transition reconcile(State &s, const std::function<bool(unsigned)> &isLive,
                     size_t &dropped) {
  dropped = 0;
  Counts before = counts(s);
  for (auto it = s.leases.begin(); it != s.leases.end();) {
    if (isLive(it->first)) { ++it; continue; }
    it = s.leases.erase(it);
    dropped++;
  }
  return diff(before, counts(s));
}

std::string serialize(const State &s) {
  std::ostringstream o;
  o << "# crate fw leases v1\n";
  o << "orig4\t" << s.orig4 << "\torig6\t" << s.orig6 << "\n";
  for (auto &kv : s.leases)
    o << kv.first << '\t' << kv.second.slot << '\t'
      << (kv.second.fwd4 ? 1 : 0) << '\t' << (kv.second.fwd6 ? 1 : 0) << '\n';
  return o.str();
}

bool parse(const std::string &text, State &out, std::string &err) {
  State st;
  std::istringstream in(text);
  std::string line;
  size_t lineNo = 0;
  while (std::getline(in, line)) {
    lineNo++;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    auto f = splitTabs(line);
    if (f.size() == 4 && f[0] == "orig4" && f[2] == "orig6") {
      long long a, b;
      if (!parseInt(f[1], -1, 1, a) || !parseInt(f[3], -1, 1, b)) {
        err = "line " + std::to_string(lineNo) + ": bad orig values";
        return false;
      }
      st.orig4 = (int)a; st.orig6 = (int)b;
      continue;
    }
    if (f.size() != 4) {
      err = "line " + std::to_string(lineNo) + ": expected 4 tab-separated fields";
      return false;
    }
    long long jid, slot, f4, f6;
    if (!parseInt(f[0], 1, 65535, jid) || !parseInt(f[1], -1, kMaxSlots - 1, slot)
        || !parseInt(f[2], 0, 1, f4) || !parseInt(f[3], 0, 1, f6)) {
      err = "line " + std::to_string(lineNo) + ": bad field value";
      return false;
    }
    Entry e;
    e.slot = (int)slot; e.fwd4 = f4 == 1; e.fwd6 = f6 == 1;
    if (!st.leases.emplace((unsigned)jid, e).second) {
      err = "line " + std::to_string(lineNo) + ": duplicate jid " + f[0];
      return false;
    }
  }
  // a slot held twice is corruption, not a state we can reason about
  std::set<int> seen;
  for (auto &kv : st.leases)
    if (kv.second.slot >= 0 && !seen.insert(kv.second.slot).second) {
      err = "slot " + std::to_string(kv.second.slot) + " held by two leases";
      return false;
    }
  out = std::move(st);
  err.clear();
  return true;
}

}
