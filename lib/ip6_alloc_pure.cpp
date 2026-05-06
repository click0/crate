// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ip6_alloc_pure.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <set>
#include <sstream>

namespace Ip6AllocPure {

namespace {

bool isHexChar(char c) {
  return (c >= '0' && c <= '9')
      || (c >= 'a' && c <= 'f')
      || (c >= 'A' && c <= 'F');
}

unsigned hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  return 10 + (c - 'A');  // assumes A-F (caller checked)
}

// Parse a single 16-bit group (1..4 hex chars). Returns true on
// success.
bool parseGroup(const std::string &s, uint16_t &out) {
  if (s.empty() || s.size() > 4) return false;
  uint32_t v = 0;
  for (char c : s) {
    if (!isHexChar(c)) return false;
    v = (v << 4) | hexVal(c);
  }
  out = static_cast<uint16_t>(v);
  return true;
}

void put16(Addr6 &a, size_t pos, uint16_t v) {
  a[pos]     = static_cast<uint8_t>(v >> 8);
  a[pos + 1] = static_cast<uint8_t>(v & 0xff);
}

uint16_t get16(const Addr6 &a, size_t pos) {
  return (uint16_t)((a[pos] << 8) | a[pos + 1]);
}

// Apply prefix mask: zero out everything past prefixLen.
void maskPrefix(Addr6 &a, unsigned prefixLen) {
  if (prefixLen >= 128) return;
  for (unsigned bit = prefixLen; bit < 128; bit++) {
    a[bit / 8] &= ~(1u << (7 - (bit % 8)));
  }
}

// Returns true if a == zero address.
bool isZero(const Addr6 &a) {
  for (auto b : a) if (b != 0) return false;
  return true;
}

// In-place increment of a 128-bit big-endian byte array. Returns
// true on success; false if it overflows (hits all-ones and wraps).
bool incrementInPlace(Addr6 &a) {
  for (int i = 15; i >= 0; i--) {
    if (++a[i] != 0) return true;
  }
  return false;  // wrapped around
}

} // anon

std::string parseIp6(const std::string &s, Addr6 &out) {
  if (s.empty()) return "IPv6 address is empty";
  if (s.size() > 64) return "IPv6 address is implausibly long";

  // Find "::" shorthand position.
  std::string before, after;
  bool hasShorthand = false;
  auto cc = s.find("::");
  if (cc != std::string::npos) {
    if (s.find("::", cc + 1) != std::string::npos)
      return "IPv6 address has more than one '::': '" + s + "'";
    before = s.substr(0, cc);
    after  = s.substr(cc + 2);
    hasShorthand = true;
  } else {
    before = s;
  }

  auto splitGroups = [](const std::string &part, std::vector<std::string> &out) -> std::string {
    if (part.empty()) return "";
    std::string cur;
    for (char c : part) {
      if (c == ':') {
        if (cur.empty()) return "empty group (consecutive ':' without '::')";
        out.push_back(cur);
        cur.clear();
      } else {
        cur += c;
      }
    }
    if (cur.empty()) return "trailing ':' without '::'";
    out.push_back(cur);
    return "";
  };

  std::vector<std::string> beforeGroups, afterGroups;
  if (auto e = splitGroups(before, beforeGroups); !e.empty())
    return "IPv6 parse: " + e + " in '" + s + "'";
  if (auto e = splitGroups(after,  afterGroups);  !e.empty())
    return "IPv6 parse: " + e + " in '" + s + "'";

  size_t total = beforeGroups.size() + afterGroups.size();
  if (total > 8) return "IPv6 has too many groups: '" + s + "'";
  if (!hasShorthand && total != 8)
    return "IPv6 needs exactly 8 groups (or '::' shorthand): '" + s + "'";
  if (hasShorthand && total == 8)
    return "IPv6 '::' shorthand needs at least one zero group: '" + s + "'";

  Addr6 a{};
  size_t pos = 0;
  for (auto &g : beforeGroups) {
    uint16_t v = 0;
    if (!parseGroup(g, v)) return "IPv6 group '" + g + "' is not 1..4 hex digits";
    put16(a, pos, v);
    pos += 2;
  }
  // Skip zero groups for shorthand (already zero-initialised).
  size_t zeros = 8 - total;
  pos += zeros * 2;
  for (auto &g : afterGroups) {
    uint16_t v = 0;
    if (!parseGroup(g, v)) return "IPv6 group '" + g + "' is not 1..4 hex digits";
    put16(a, pos, v);
    pos += 2;
  }
  out = a;
  return "";
}

std::string parseCidr6(const std::string &cidr, Network6 &out) {
  auto slash = cidr.find('/');
  if (slash == std::string::npos)
    return "missing CIDR mark '/' in '" + cidr + "'";
  if (cidr.find('/', slash + 1) != std::string::npos)
    return "more than one '/' in '" + cidr + "'";

  Addr6 base{};
  if (auto e = parseIp6(cidr.substr(0, slash), base); !e.empty())
    return e;

  auto prefStr = cidr.substr(slash + 1);
  if (prefStr.empty()) return "empty prefix length in '" + cidr + "'";
  if (prefStr.size() > 3) return "implausible prefix length in '" + cidr + "'";
  for (char c : prefStr)
    if (c < '0' || c > '9') return "non-numeric prefix length in '" + cidr + "'";
  unsigned p = 0;
  for (char c : prefStr) p = p * 10 + (c - '0');
  if (p < 1 || p > 128)
    return "IPv6 prefix length out of range (1..128): '" + cidr + "'";

  // Reject unaligned base (host bits set).
  Addr6 masked = base;
  maskPrefix(masked, p);
  if (masked != base)
    return "IPv6 base address is not aligned to /" + std::to_string(p)
         + " (host bits set): '" + cidr + "'";

  out.base = base;
  out.prefixLen = p;
  return "";
}

std::string formatIp6(const Addr6 &addr) {
  // Decompose into 8 groups, find longest run of >=2 zeros.
  uint16_t g[8];
  for (int i = 0; i < 8; i++) g[i] = get16(addr, i * 2);

  int bestStart = -1, bestLen = 0;
  int curStart = -1, curLen = 0;
  for (int i = 0; i < 8; i++) {
    if (g[i] == 0) {
      if (curStart < 0) { curStart = i; curLen = 1; }
      else              { curLen++; }
      if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
    } else {
      curStart = -1; curLen = 0;
    }
  }
  // RFC 5952 §4.2.2: only collapse runs of 2+.
  if (bestLen < 2) { bestStart = -1; bestLen = 0; }

  std::ostringstream os;
  int i = 0;
  while (i < 8) {
    if (i == bestStart) {
      os << "::";
      i += bestLen;
      // If the collapse runs to the end ("fe80::"), the "::" we
      // just emitted is the whole tail — done. Otherwise the next
      // iteration writes the next non-zero group without a leading
      // colon (the second ':' of "::" already serves).
      continue;
    }
    if (i > 0 && i != bestStart + bestLen) os << ":";
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%x", g[i]);
    os << buf;
    i++;
  }
  return os.str();
}

Addr6 gatewayFor(const Network6 &n) {
  Addr6 g = n.base;
  incrementInPlace(g);   // base + 1
  return g;
}

Addr6 allocateNext(const Network6 &pool, const std::vector<Addr6> &taken) {
  std::set<Addr6> takenSet(taken.begin(), taken.end());
  Addr6 candidate = pool.base;
  // Skip base (.::0) and gateway (.::1) — start at base + 2.
  if (!incrementInPlace(candidate)) return Addr6{};
  if (!incrementInPlace(candidate)) return Addr6{};

  // Scan up to a reasonable cap so a misconfigured /127 pool doesn't
  // turn into a 2^126 loop. Bound = max(2^16, jails-on-host * 2).
  // For typical /64 pools this terminates in O(jails) iterations.
  for (int i = 0; i < 65536; i++) {
    if (!inPool(pool, candidate)) return Addr6{};   // ran off pool
    if (takenSet.count(candidate) == 0)
      return candidate;
    if (!incrementInPlace(candidate)) return Addr6{};
  }
  return Addr6{};   // cap reached — give up
}

bool inPool(const Network6 &pool, const Addr6 &addr) {
  Addr6 masked = addr;
  maskPrefix(masked, pool.prefixLen);
  return masked == pool.base;
}

std::string parseLeaseLine6(const std::string &line, Lease6 &out) {
  auto sp = line.find(' ');
  if (sp == std::string::npos) return "no space separator";
  auto name = line.substr(0, sp);
  auto ip   = line.substr(sp + 1);
  if (name.empty()) return "empty name";
  Addr6 a{};
  if (auto e = parseIp6(ip, a); !e.empty())
    return "ip parse: " + e;
  out.name = name;
  out.ip = a;
  return "";
}

std::string formatLeaseLine6(const Lease6 &l) {
  return l.name + " " + formatIp6(l.ip);
}

} // namespace Ip6AllocPure
