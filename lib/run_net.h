// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

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

struct BridgeInfo {
  std::string ifaceA;       // host-side epair (member of bridge)
  std::string ifaceB;       // jail-side epair
  std::string bridgeIface;  // e.g. "bridge0"
  unsigned num;
};

// Detect host's default gateway interface, IP, and LAN
GatewayInfo detectGateway();

// Create an epair interface pair and assign IPs (NAT mode)
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

// Bridge mode: create epair, add to existing bridge, move b-side into jail
BridgeInfo createBridgeEpair(int jid, const std::string &jidStr,
    const std::string &bridgeIface,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail);

// Bridge mode: remove epair from bridge and destroy it
void destroyBridgeEpair(const BridgeInfo &info);

// Ensure if_bridge kernel module is loaded
void ensureBridgeModule();

// Configure DHCP on jail-side interface (runs dhclient inside jail)
void configureDhcp(const std::string &jailSideIface,
    const std::string &jailPath, int jid, const std::string &jidStr,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail);

// Configure static IP on jail-side interface
void configureStaticIp(const std::string &jailSideIface,
    const std::string &ip, const std::string &gateway, int jid,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail);

// Generate deterministic MAC address pair from jail name + interface name
// Returns {hostSideMac, jailSideMac}. Prefix: 58:9c:fc (FreeBSD vendor OUI).
std::pair<std::string,std::string> generateStaticMac(
    const std::string &jailName, const std::string &ifaceName);

// Set MAC address on an interface
void setMacAddress(const std::string &iface, const std::string &mac);

// Create a VLAN interface inside the jail on top of a parent interface
void createVlanInJail(int jid, const std::string &parentIface, int vlanId,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail);

}
