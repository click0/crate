// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "net.h"
#include "util.h"
#include "err.h"

#include <string>
#include <vector>
#include <fstream>

namespace Net {

//
// iface
//

std::vector<IpInfo> getIfaceIp4Addresses(const std::string &ifaceName) {
  std::vector<IpInfo> addrs;
  struct ifaddrs *ifap;
  int res;
  char host[NI_MAXHOST];
  char netmask[NI_MAXHOST];

  // helpers
  auto countBits = [](auto i) {
    unsigned cnt = 0;
    for (decltype(i) bit = 1; bit; bit <<= 1)
      if (i & bit)
        cnt++;
    return cnt;
  };
  auto netFromHostAndNatmaskV4 = [countBits](const std::string &host, const std::string &netmask) {
    auto hostVec =    Util::splitString(host, ".");
    auto netmaskVec = Util::splitString(netmask, ".");
    unsigned nbits = 0;
    std::ostringstream ss;
    for (int i = 0; i < 4; i++) {
      if (i > 0)
        ss << ".";
      uint8_t mask = std::stoul(netmaskVec[i]);
      ss << (std::stoul(hostVec[i]) & mask);
      nbits += countBits(mask);
    }
    ss << "/" << nbits;
    return ss.str();
  };

  // get all addresses of all interfaces
  if (::getifaddrs(&ifap) == -1)
    ERR2("network interface", "getifaddrs() failed: " << strerror(errno))
  RunAtEnd destroyAddresses([ifap]() {
    ::freeifaddrs(ifap);
  });

  // filter only IPv4 addresses for the requested interface
  for (struct ifaddrs *a = ifap; a; a = a->ifa_next)
    if (a->ifa_addr->sa_family == AF_INET && ::strcmp(a->ifa_name, ifaceName.c_str()) == 0) { // IPv4 for the requested interface
      res = ::getnameinfo(a->ifa_addr,
                          sizeof(struct sockaddr_in),
                          host, NI_MAXHOST,
                          nullptr, 0, NI_NUMERICHOST);
      if (res != 0)
        ERR2("get network interface address", "getnameinfo() failed: " << ::gai_strerror(res));

      res = ::getnameinfo(a->ifa_netmask,
                          sizeof(struct sockaddr_in),
                          netmask, NI_MAXHOST,
                          nullptr, 0, NI_NUMERICHOST);
      if (res != 0)
        ERR2("get network interface address", "getnameinfo() failed: " << ::gai_strerror(res));

      addrs.push_back({host, netmask, netFromHostAndNatmaskV4(host, netmask)});
    }

  return addrs;
}

std::vector<Ip6Info> getIfaceIp6Addresses(const std::string &ifaceName) {
  std::vector<Ip6Info> addrs;
  struct ifaddrs *ifap;

  if (::getifaddrs(&ifap) == -1)
    ERR2("network interface", "getifaddrs() failed: " << strerror(errno))
  RunAtEnd destroyAddresses([ifap]() {
    ::freeifaddrs(ifap);
  });

  for (struct ifaddrs *a = ifap; a; a = a->ifa_next) {
    if (a->ifa_addr == nullptr) continue;
    if (a->ifa_addr->sa_family != AF_INET6) continue;
    if (::strcmp(a->ifa_name, ifaceName.c_str()) != 0) continue;

    char host[NI_MAXHOST];
    int res = ::getnameinfo(a->ifa_addr, sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
    if (res != 0)
      continue; // skip addresses we can't resolve

    // Strip zone ID (%iface) from link-local addresses
    std::string addr = host;
    auto pctPos = addr.find('%');
    if (pctPos != std::string::npos)
      addr = addr.substr(0, pctPos);

    // Determine prefix length from netmask
    unsigned prefixLen = 0;
    if (a->ifa_netmask) {
      auto *sin6 = (struct sockaddr_in6 *)a->ifa_netmask;
      for (int i = 0; i < 16; i++) {
        uint8_t byte = sin6->sin6_addr.s6_addr[i];
        while (byte) {
          prefixLen += (byte & 0x80) ? 1 : 0;
          byte <<= 1;
        }
      }
    }

    // Determine scope
    std::string scope;
    if (addr.substr(0, 4) == "fe80")
      scope = "link-local";
    else if (addr.substr(0, 2) == "fd" || addr.substr(0, 2) == "fc")
      scope = "ula";
    else if (addr == "::1")
      scope = "loopback";
    else
      scope = "global";

    addrs.push_back({addr, prefixLen, scope});
  }

  return addrs;
}

bool isIpv6Address(const std::string &addr) {
  struct in6_addr result;
  return ::inet_pton(AF_INET6, addr.c_str(), &result) == 1;
}

std::string getNameserverIp() {
  std::ifstream resolv("/etc/resolv.conf");
  if (!resolv.is_open())
    ERR2("network", "failed to open /etc/resolv.conf")
  std::string line;
  while (std::getline(resolv, line)) {
    // match "nameserver <ip>" (case insensitive prefix)
    if (line.size() > 11 &&
        (line.substr(0, 11) == "nameserver " || line.substr(0, 11) == "NAMESERVER " || line.substr(0, 11) == "Nameserver ")) {
      auto ip = Util::stripTrailingSpace(line.substr(11));
      if (!ip.empty())
        return ip;
    }
  }
  ERR2("network", "no nameserver found in /etc/resolv.conf")
  return ""; // unreachable
}

}
