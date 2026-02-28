// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#pragma once

#include <string>
#include <vector>

namespace Net {

typedef std::tuple<std::string, std::string, std::string> IpInfo;
// IPv6 info: {address, prefixlen, scope}
typedef std::tuple<std::string, unsigned, std::string> Ip6Info;

std::vector<IpInfo> getIfaceIp4Addresses(const std::string &ifaceName);
std::vector<Ip6Info> getIfaceIp6Addresses(const std::string &ifaceName);
std::string getNameserverIp();
bool isIpv6Address(const std::string &addr);

}
