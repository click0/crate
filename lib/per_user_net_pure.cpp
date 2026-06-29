// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "per_user_net_pure.h"

#include <array>
#include <cctype>
#include <sstream>
#include <vector>

namespace PerUserNetPure {

namespace {

// --- IPv4 helpers ---

bool parseIpv4(const std::string &s, uint32_t &out) {
  uint32_t acc = 0;
  size_t i = 0;
  for (int octet = 0; octet < 4; octet++) {
    if (i >= s.size()) return false;
    if (!std::isdigit((unsigned char)s[i])) return false;
    // Reject leading zeros for >1-digit octets (octal foot-gun).
    size_t start = i;
    unsigned v = 0;
    while (i < s.size() && std::isdigit((unsigned char)s[i])) {
      v = v * 10 + (unsigned)(s[i] - '0');
      if (v > 255) return false;
      i++;
    }
    if (i - start > 1 && s[start] == '0') return false;
    acc = (acc << 8) | v;
    if (octet < 3) {
      if (i >= s.size() || s[i] != '.') return false;
      i++;
    }
  }
  if (i != s.size()) return false;
  out = acc;
  return true;
}

std::string formatIpv4(uint32_t addr) {
  std::ostringstream o;
  o << ((addr >> 24) & 0xff) << '.'
    << ((addr >> 16) & 0xff) << '.'
    << ((addr >>  8) & 0xff) << '.'
    << (addr & 0xff);
  return o.str();
}

// Split "<addr>/<prefix>". Returns {addr, prefix, error}.
struct CidrSplit {
  std::string addr;
  unsigned prefix = 0;
  std::string error;
};

CidrSplit splitCidr(const std::string &cidr) {
  auto slash = cidr.find('/');
  if (slash == std::string::npos)
    return {"", 0, "missing '/' in CIDR"};
  CidrSplit r;
  r.addr = cidr.substr(0, slash);
  std::string plen = cidr.substr(slash + 1);
  if (plen.empty() || plen.size() > 3)
    return {"", 0, "prefix length empty or too long"};
  unsigned p = 0;
  for (char c : plen) {
    if (!std::isdigit((unsigned char)c))
      return {"", 0, "prefix length not a number"};
    p = p * 10 + (unsigned)(c - '0');
    if (p > 128) return {"", 0, "prefix length out of range"};
  }
  r.prefix = p;
  return r;
}

// --- IPv6 helpers ---
//
// We model an IPv6 address as 8 16-bit groups in big-endian. parse
// accepts compressed (::) form and full 8-group form. The slot
// arithmetic operates on the byte-aligned region just below the
// master prefix.

bool parseIpv6(const std::string &s, std::array<uint16_t, 8> &out) {
  // Reject empty / oversized strings early.
  if (s.empty() || s.size() > 45) return false;

  // Locate '::' (allow at most one).
  size_t doubleColon = s.find("::");
  if (doubleColon != std::string::npos
      && s.find("::", doubleColon + 1) != std::string::npos)
    return false;

  std::vector<uint16_t> head;
  std::vector<uint16_t> tail;
  std::string cur;
  bool seenDoubleColon = false;
  bool inTail = false;

  auto flush = [&](std::vector<uint16_t> &dst) -> bool {
    if (cur.empty()) return true;
    if (cur.size() > 4) return false;
    uint16_t v = 0;
    for (char c : cur) {
      uint16_t d;
      if (c >= '0' && c <= '9')      d = (uint16_t)(c - '0');
      else if (c >= 'a' && c <= 'f') d = (uint16_t)(10 + c - 'a');
      else if (c >= 'A' && c <= 'F') d = (uint16_t)(10 + c - 'A');
      else return false;
      v = (uint16_t)((v << 4) | d);
    }
    dst.push_back(v);
    cur.clear();
    return true;
  };

  for (size_t i = 0; i < s.size(); i++) {
    char c = s[i];
    if (c == ':') {
      if (i + 1 < s.size() && s[i + 1] == ':') {
        // '::' boundary
        if (seenDoubleColon) return false;
        seenDoubleColon = true;
        if (!flush(inTail ? tail : head)) return false;
        inTail = true;
        i++;  // skip the second colon
        continue;
      }
      if (!flush(inTail ? tail : head)) return false;
    } else {
      cur.push_back(c);
    }
  }
  if (!flush(inTail ? tail : head)) return false;

  if (seenDoubleColon) {
    if (head.size() + tail.size() > 8) return false;
    size_t fill = 8 - head.size() - tail.size();
    size_t k = 0;
    for (auto v : head) out[k++] = v;
    for (size_t f = 0; f < fill; f++) out[k++] = 0;
    for (auto v : tail) out[k++] = v;
  } else {
    if (head.size() != 8) return false;
    for (size_t k = 0; k < 8; k++) out[k] = head[k];
  }
  return true;
}

std::string formatIpv6(const std::array<uint16_t, 8> &g) {
  std::ostringstream o;
  for (size_t i = 0; i < 8; i++) {
    if (i) o << ':';
    // Don't pad — use lowercase hex without leading zeros, matching
    // the canonical text form. We don't emit a "::" compression
    // here because operator scripts often grep for the literal
    // sub-CIDR; leaving full-form keeps that simple.
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%x", (unsigned)g[i]);
    o << buf;
  }
  return o.str();
}

} // anon

Result composeIpv4(const std::string &masterCidr,
                   unsigned subPrefixLen,
                   uint32_t uid) {
  auto split = splitCidr(masterCidr);
  if (!split.error.empty()) return {"", "master: " + split.error};
  if (split.prefix > 32) return {"", "master IPv4 prefix > 32"};
  if (subPrefixLen > 32) return {"", "sub prefix > 32"};
  if (subPrefixLen <= split.prefix)
    return {"", "sub prefix must be greater than master prefix"};
  unsigned slotBits = subPrefixLen - split.prefix;
  if (slotBits > 24)
    return {"", "slot space too large (>24 bits)"};

  uint32_t addr = 0;
  if (!parseIpv4(split.addr, addr))
    return {"", "master address malformed"};

  // Mask master so caller-supplied non-canonical addrs (10.66.5.0/16)
  // don't lake into the slot bits.
  uint32_t masterMask = split.prefix == 0
                          ? 0
                          : (uint32_t)(0xffffffffULL << (32 - split.prefix));
  uint32_t base = addr & masterMask;

  // 1.1.18: refuse to silently wrap a uid that doesn't fit the slot
  // space. Pre-1.1.18 this did `uid & (slotCount-1)`, so two uids that
  // collide modulo 2^slotBits got the SAME sub-CIDR — defeating the
  // per-operator network separation this function exists to provide.
  // Error loudly so the operator sizes the master CIDR / sub-prefix to
  // their uid range. (slotBits <= 24 here, so 1u<<slotBits is safe.)
  if (uid >= (1u << slotBits))
    return {"", "uid " + std::to_string(uid) + " exceeds the " +
                std::to_string(slotBits) + "-bit per-user slot space "
                "(max uid " + std::to_string((1u << slotBits) - 1) +
                "); widen the master IPv4 CIDR or shrink the sub-prefix"};

  uint32_t slot = uid;
  uint32_t slotShift = 32 - subPrefixLen;
  uint32_t subBase = base | (slot << slotShift);

  std::ostringstream o;
  o << formatIpv4(subBase) << "/" << subPrefixLen;
  return {o.str(), ""};
}

Result composeIpv6(const std::string &masterCidr,
                   unsigned subPrefixLen,
                   uint32_t uid) {
  auto split = splitCidr(masterCidr);
  if (!split.error.empty()) return {"", "master: " + split.error};
  if (split.prefix > 128) return {"", "master IPv6 prefix > 128"};
  if (subPrefixLen > 128) return {"", "sub prefix > 128"};
  if (subPrefixLen <= split.prefix)
    return {"", "sub prefix must be greater than master prefix"};
  unsigned slotBits = subPrefixLen - split.prefix;
  if (slotBits > 32)
    return {"", "slot space too large (>32 bits)"};

  std::array<uint16_t, 8> g{};
  if (!parseIpv6(split.addr, g))
    return {"", "master address malformed"};

  // Apply master mask so non-canonical bits below the prefix are
  // cleared. Operate on the flat 128-bit representation.
  std::array<uint8_t, 16> bytes{};
  for (size_t i = 0; i < 8; i++) {
    bytes[i*2]     = (uint8_t)(g[i] >> 8);
    bytes[i*2 + 1] = (uint8_t)(g[i] & 0xff);
  }
  for (size_t bit = split.prefix; bit < 128; bit++) {
    bytes[bit / 8] &= (uint8_t)~(1u << (7 - (bit % 8)));
  }

  // 1.1.18: same anti-collision guard as composeIpv4 — error rather
  // than silently wrap a uid that exceeds the slot space. (slotBits <=
  // 32; 1ULL<<32 is fine in uint64_t, and a uint32_t uid is always
  // < 2^32, so a 32-bit slot space accepts every uid.)
  if ((uint64_t)uid >= (1ULL << slotBits))
    return {"", "uid " + std::to_string(uid) + " exceeds the " +
                std::to_string(slotBits) + "-bit per-user slot space; "
                "widen the master IPv6 CIDR or shrink the sub-prefix"};

  // Set slot bits at [masterPrefix .. subPrefixLen).
  uint64_t slot = (uint64_t)uid;
  for (unsigned i = 0; i < slotBits; i++) {
    unsigned bitFromTop = slotBits - 1 - i;     // MSB of slot first
    if ((slot >> bitFromTop) & 1ULL) {
      unsigned absBit = split.prefix + i;
      bytes[absBit / 8] |= (uint8_t)(1u << (7 - (absBit % 8)));
    }
  }

  for (size_t i = 0; i < 8; i++) {
    g[i] = (uint16_t)((bytes[i*2] << 8) | bytes[i*2 + 1]);
  }

  std::ostringstream o;
  o << formatIpv6(g) << "/" << subPrefixLen;
  return {o.str(), ""};
}

} // namespace PerUserNetPure
