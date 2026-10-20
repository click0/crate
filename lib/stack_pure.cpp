// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "stack_pure.h"
#include "err.h"
#include "name_limits.h"   // 1.1.45: kJailName

#include <algorithm>
#include <cctype>
#include <set>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <map>
#include <queue>
#include <sstream>

namespace StackPure {

bool parseCidr(const std::string &cidr, uint32_t &baseAddr, unsigned &prefixLen) {
  auto slashPos = cidr.find('/');
  if (slashPos == std::string::npos)
    return false;
  auto addrStr = cidr.substr(0, slashPos);
  auto suffix = cidr.substr(slashPos + 1);
  // Reject leading '-' explicitly: std::stoul wraps "-1" to ULONG_MAX,
  // which would otherwise pass through as a "valid" prefix.
  if (suffix.empty() || suffix.front() == '-')
    return false;
  try {
    std::size_t pos = 0;
    auto p = std::stoul(suffix, &pos);
    if (pos != suffix.size())
      return false;
    if (p > 32)  // valid IPv4 prefix range is 0..32
      return false;
    prefixLen = static_cast<unsigned>(p);
  } catch (const std::invalid_argument &) {
    return false;
  } catch (const std::out_of_range &) {
    return false;
  }
  struct in_addr addr;
  if (inet_pton(AF_INET, addrStr.c_str(), &addr) != 1)
    return false;
  baseAddr = ntohl(addr.s_addr);
  return true;
}

std::string ipToString(uint32_t ip) {
  struct in_addr addr;
  addr.s_addr = htonl(ip);
  char buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &addr, buf, sizeof(buf));
  return buf;
}

bool isIpv6Address(const std::string &addr) {
  struct in6_addr result;
  return ::inet_pton(AF_INET6, addr.c_str(), &result) == 1;
}

std::string ipFromCidr(const std::string &cidr) {
  auto pos = cidr.find('/');
  return pos != std::string::npos ? cidr.substr(0, pos) : cidr;
}

std::string buildHostsEntries(const std::map<std::string, std::string> &nameToIp) {
  std::ostringstream ss;
  for (auto &kv : nameToIp)
    ss << kv.second << " " << kv.first << "\n";
  return ss.str();
}

std::string validateStackName(const std::string &name) {
  if (name.empty()) return "name is empty";
  // 1.1.45: same ceiling as every other jail name (NameLimits::kJailName);
  // 64 was a local drift that rejected names `crate run --name` accepts.
  if (name.size() > NameLimits::kJailName)
    return "name is longer than " + std::to_string(NameLimits::kJailName) + " chars";
  if (name == "." || name == "..") return "name is reserved";
  if (name.front() == '-') return "name must not start with '-'";
  for (char c : name) {
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    if (!ok)
      return "name contains an invalid character (allowed: [A-Za-z0-9._-])";
  }
  return "";
}

std::string validateStackIp(const std::string &ip) {
  if (ip.empty()) return "address is empty";
  // Charset gate first: this is what makes the value inert inside the
  // single-quoted shell fragment regardless of what inet_pton thinks.
  for (char c : ip) {
    bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
           || (c >= 'A' && c <= 'F') || c == '.' || c == ':' || c == '/';
    if (!ok)
      return "address contains an invalid character";
  }
  auto slash = ip.find('/');
  auto bare = (slash == std::string::npos) ? ip : ip.substr(0, slash);
  struct in_addr a4;
  struct in6_addr a6;
  long maxPrefix;
  if (::inet_pton(AF_INET, bare.c_str(), &a4) == 1)       maxPrefix = 32;
  else if (::inet_pton(AF_INET6, bare.c_str(), &a6) == 1) maxPrefix = 128;
  else return "address is neither a valid IPv4 nor IPv6 literal";
  // 1.1.27: the 1.1.25 version validated only the address part, so
  // `10.0.0.5/999`, `10.0.0.5/abc` and `10.0.0.5/` all passed (the
  // charset gate admits '/' and hex letters). Shell-inert, but garbage
  // for /etc/hosts. Require a bare decimal prefix within the family's
  // range when a '/' is present.
  if (slash != std::string::npos) {
    auto suffix = ip.substr(slash + 1);
    if (suffix.empty() || suffix.size() > 3) return "CIDR prefix is malformed";
    long p = 0;
    for (char c : suffix) {
      if (c < '0' || c > '9') return "CIDR prefix must be numeric";
      p = p * 10 + (c - '0');
    }
    if (p > maxPrefix) return "CIDR prefix is out of range for the address family";
  }
  return "";
}

// topoSort is templated and lives in stack_pure.h.

// --- 1.1.45 ---

bool jailNameMatchesContainer(const std::string &jailName, const std::string &container) {
  if (container.empty()) return false;
  const std::string prefix = container + "_pid";
  if (jailName.size() <= prefix.size()) return false;
  if (jailName.compare(0, prefix.size(), prefix) != 0) return false;
  for (size_t i = prefix.size(); i < jailName.size(); i++)
    if (!std::isdigit((unsigned char)jailName[i])) return false;
  return true;
}

std::vector<unsigned> ipfwRuleNumbers(const std::string &ipfwListOutput) {
  std::vector<unsigned> out;
  std::istringstream is(ipfwListOutput);
  std::string line;
  while (std::getline(is, line)) {
    size_t i = 0;
    while (i < line.size() && line[i] == ' ') i++;
    size_t start = i;
    unsigned long v = 0;
    while (i < line.size() && std::isdigit((unsigned char)line[i]) && i - start < 6) {
      v = v * 10 + (unsigned long)(line[i] - '0');
      i++;
    }
    if (i == start || v == 0 || v > 65535) continue;          // not a rule line
    if (i < line.size() && line[i] != ' ' && line[i] != '\t') continue;
    out.push_back((unsigned)v);
  }
  return out;
}

unsigned freePolicySlot(const std::vector<unsigned> &used,
                        unsigned base, unsigned end, unsigned width) {
  if (width == 0 || base > end) return 0;
  std::set<unsigned> taken(used.begin(), used.end());
  for (unsigned slot = base; slot + width - 1 <= end; slot += width) {
    auto it = taken.lower_bound(slot);
    if (it == taken.end() || *it > slot + width - 1) return slot;
  }
  return 0;
}

std::vector<unsigned> policyRulesForBridge(const std::string &ipfwListOutput,
                                           const std::string &bridge,
                                           unsigned lo, unsigned hi) {
  std::vector<unsigned> out;
  if (bridge.empty()) return out;
  std::istringstream is(ipfwListOutput);
  std::string line;
  const std::string needle = " via " + bridge;
  while (std::getline(is, line)) {
    auto nums = ipfwRuleNumbers(line);
    if (nums.empty()) continue;
    unsigned n = nums[0];
    if (n < lo || n > hi) continue;
    // "via <bridge>" must be a whole token: " via bridge0" followed by
    // end of line or a space (not "bridge01").
    size_t p = line.find(needle);
    if (p == std::string::npos) continue;
    size_t after = p + needle.size();
    if (after < line.size() && line[after] != ' ' && line[after] != '\t' && line[after] != '\r') continue;
    if (std::find(out.begin(), out.end(), n) == out.end()) out.push_back(n);
  }
  return out;
}

}
