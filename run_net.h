// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#pragma once

#include "util.h"

#include <string>
#include <functional>

namespace RunNet {

struct GatewayInfo {
  std::string iface;  // e.g. "em0"
  std::string hostIP; // e.g. "192.168.1.10"
  std::string hostLAN; // e.g. "192.168.1.0/24"
};

struct EpairInfo {
  std::string ifaceA;  // host side, e.g. "epair0a"
  std::string ifaceB;  // jail side, e.g. "epair0b"
  std::string ipA;     // host side IP, e.g. "10.0.0.100"
  std::string ipB;     // jail side IP, e.g. "10.0.0.101"
  unsigned num;        // epair number
};

// Detect host's default gateway interface, IP, and LAN
GatewayInfo detectGateway();

// Create an epair interface pair and assign IPs
EpairInfo createEpair(int jid, const std::string &jidStr,
                      const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail);

// Destroy an epair interface (host side — jail side is auto-destroyed with jail)
void destroyEpair(const std::string &ifaceA);

// Convert epair number to 10.0.0.0/8 IP address
std::string epairNumToIp(unsigned epairNum, unsigned ipIdx);

// Set up ipfw NAT + filter rules for a container, returns cleanup callback
// fwSlot is allocated from Ctx::FwSlots
RunAtEnd setupFirewallRules(const class Spec &spec, const EpairInfo &epair,
                            const GatewayInfo &gw, unsigned fwSlot,
                            const std::string &nameserverIp,
                            int origIpForwarding, bool logProgress);

// Set up per-container pf anchor rules, returns cleanup callback
RunAtEnd setupPfAnchor(const class Spec &spec, const EpairInfo &epair,
                       const std::string &jailXname, bool logProgress);

}
