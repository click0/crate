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
  try {
    std::size_t pos = 0;
    auto suffix = cidr.substr(slashPos + 1);
    prefixLen = std::stoul(suffix, &pos);
    if (pos != suffix.size())
      return false;
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

// topoSort is templated and lives in stack_pure.h.

}
