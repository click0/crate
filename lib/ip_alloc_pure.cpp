// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ip_alloc_pure.h"

#include <algorithm>
#include <cstdio>
#include <set>
#include <sstream>

namespace IpAllocPure {

namespace {

bool parseOctet(const std::string &s, uint32_t &out) {
  if (s.empty() || s.size() > 3) return false;
  for (char c : s) if (c < '0' || c > '9') return false;
  // Reject leading zeros for octets > 0 ("01") to avoid the
  // octal-confusion class of bugs in legacy code that stat()s
  // unparsable IPs.
  if (s.size() > 1 && s[0] == '0') return false;
  uint32_t n = 0;
  for (char c : s) {
    n = n * 10 + (uint32_t)(c - '0');
    if (n > 255) return false;
  }
  out = n;
  return true;
}

} // anon

std::string parseIp(const std::string &s, uint32_t &out) {
  std::vector<std::string> parts;
  std::string cur;
  for (char c : s) {
    if (c == '.') {
      parts.push_back(cur);
      cur.clear();
    } else {
      cur += c;
    }
  }
  parts.push_back(cur);
  if (parts.size() != 4) return "IP must have 4 dotted octets";
  uint32_t addr = 0;
  for (const auto &p : parts) {
    uint32_t o = 0;
    if (!parseOctet(p, o)) return "invalid octet '" + p + "'";
    addr = (addr << 8) | o;
  }
  out = addr;
  return "";
}

std::string formatIp(uint32_t addr) {
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                (addr >> 24) & 0xffu,
                (addr >> 16) & 0xffu,
                (addr >>  8) & 0xffu,
                (addr >>  0) & 0xffu);
  return buf;
}

std::string parseCidr(const std::string &cidr, Network &out) {
  auto slash = cidr.find('/');
  if (slash == std::string::npos)
    return "CIDR missing '/'";
  std::string ipPart  = cidr.substr(0, slash);
  std::string prePart = cidr.substr(slash + 1);
  if (prePart.empty()) return "CIDR prefix empty";
  for (char c : prePart) if (c < '0' || c > '9') return "CIDR prefix not numeric";
  unsigned prefix = 0;
  {
    uint32_t n = 0;
    for (char c : prePart) {
      n = n * 10 + (uint32_t)(c - '0');
      if (n > 32) return "CIDR prefix out of range (0..32)";
    }
    prefix = n;
  }
  if (prefix < 1 || prefix > 30)
    return "CIDR prefix out of supported range (1..30)";
  uint32_t addr = 0;
  if (auto e = parseIp(ipPart, addr); !e.empty())
    return "CIDR address: " + e;
  // Mask alignment.
  uint32_t mask = (prefix == 32) ? 0xFFFFFFFFu
                                 : (~((1u << (32 - prefix)) - 1u));
  if ((addr & mask) != addr)
    return "CIDR base address '" + ipPart
         + "' is not aligned to /" + std::to_string(prefix);
  out.base      = addr;
  out.prefixLen = prefix;
  return "";
}

uint32_t gatewayFor(const Network &n) {
  return n.base + 1;
}

uint32_t broadcastFor(const Network &n) {
  uint32_t hostMask = (n.prefixLen == 32) ? 0u
                       : ((1u << (32 - n.prefixLen)) - 1u);
  return n.base | hostMask;
}

uint32_t allocateNext(const Network &pool, const std::vector<uint32_t> &taken) {
  uint32_t bcast = broadcastFor(pool);
  uint32_t gw    = gatewayFor(pool);
  std::set<uint32_t> takenSet(taken.begin(), taken.end());
  // Scan from pool.base + 2 (skip network + gateway) up to broadcast - 1.
  for (uint32_t a = pool.base + 2; a < bcast; a++) {
    if (a == gw) continue;
    if (takenSet.count(a)) continue;
    return a;
  }
  return 0;
}

namespace {

bool nameLooksValid(const std::string &n) {
  if (n.empty() || n.size() > 64) return false;
  for (char c : n) {
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9')
           || c == '.' || c == '_' || c == '-';
    if (!ok) return false;
  }
  return true;
}

} // anon

std::string parseLeaseLine(const std::string &line, Lease &out) {
  if (line.empty()) return "lease line is empty";
  // Find the single space separator.
  auto sp = line.find(' ');
  if (sp == std::string::npos) return "lease line missing space separator";
  std::string name = line.substr(0, sp);
  std::string ip   = line.substr(sp + 1);
  // No additional whitespace permitted.
  if (name.find_first_of(" \t\r\n") != std::string::npos)
    return "name has internal whitespace";
  if (ip.find_first_of(" \t\r\n") != std::string::npos)
    return "ip has internal whitespace";
  if (!nameLooksValid(name))
    return "invalid jail name '" + name + "'";
  uint32_t addr = 0;
  if (auto e = parseIp(ip, addr); !e.empty())
    return "lease ip: " + e;
  out.name = name;
  out.ip   = addr;
  return "";
}

std::string formatLeaseLine(const Lease &l) {
  return l.name + " " + formatIp(l.ip);
}

} // namespace IpAllocPure
