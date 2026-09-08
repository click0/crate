// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "stack_pure.h"
#include "err.h"

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
  if (name.size() > 64) return "name is longer than 64 chars";
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
  auto bare = ipFromCidr(ip);
  struct in_addr a4;
  struct in6_addr a6;
  if (::inet_pton(AF_INET, bare.c_str(), &a4) == 1) return "";
  if (::inet_pton(AF_INET6, bare.c_str(), &a6) == 1) return "";
  return "address is neither a valid IPv4 nor IPv6 literal";
}

// topoSort is templated and lives in stack_pure.h.

}
