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

// Set up ipfw NAT + filter rules for a container, returns cleanup callback.
// fwSlot is allocated from Ctx::FwSlots.
// ipv6Addr / ipv6Iface: jail-side IPv6 address and outbound interface
// (pass empty strings to skip IPv6 rules).
RunAtEnd setupFirewallRules(const class Spec &spec, const EpairInfo &epair,
                            const GatewayInfo &gw, unsigned fwSlot,
                            const std::string &nameserverIp,
                            int origIpForwarding, bool logProgress,
                            const std::string &ipv6Addr = {},
                            const std::string &ipv6Iface = {});

struct PassthroughInfo {
  std::string iface;  // e.g. "vtnet1" — MUST reclaim before jail destruction
};

struct NetgraphInfo {
  std::string ngIface;    // eiface name inside jail, e.g. "ngeth0"
  std::string physIface;  // physical interface, e.g. "em0"
  std::string bridgeNode; // ng_bridge node name for cleanup
};

// Bridge mode: create epair, add to existing bridge, move b-side into jail
BridgeInfo createBridgeEpair(int jid, const std::string &jidStr,
    const std::string &bridgeIface,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail);

// Bridge mode: remove epair from bridge and destroy it
void destroyBridgeEpair(const BridgeInfo &info);

// Passthrough mode: pass a physical interface directly into jail
PassthroughInfo passthroughInterface(int jid, const std::string &jidStr,
    const std::string &iface,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail);

// Passthrough mode: reclaim interface from jail back to host
// CRITICAL: must be called BEFORE jail is destroyed, or the NIC is lost until reboot
void reclaimPassthroughInterface(const PassthroughInfo &info,
    const std::string &jailName);

// Ensure if_bridge kernel module is loaded
void ensureBridgeModule();

// Ensure netgraph kernel modules are loaded (ng_ether, ng_bridge, ng_eiface)
void ensureNetgraphModules();

// Netgraph mode: create ng_bridge + eiface, move into jail
NetgraphInfo createNetgraphInterface(int jid, const std::string &jidStr,
    const std::string &physIface, const std::string &jailName,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail);

// Netgraph mode: destroy ng_bridge node
void destroyNetgraphInterface(const NetgraphInfo &info);

// Configure DHCP on jail-side interface (runs dhclient inside jail)
void configureDhcp(const std::string &jailSideIface,
    const std::string &jailPath, int jid, const std::string &jidStr,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail);

// Configure static IP on jail-side interface
void configureStaticIp(const std::string &jailSideIface,
    const std::string &ip, const std::string &gateway, int jid,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail);

// Configure IPv6 SLAAC on jail-side interface (accept_rtadv + rtsol)
void configureSlaac(const std::string &jailSideIface,
    const std::string &jailPath, int jid, const std::string &jidStr,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail);

// Configure static IPv6 address on jail-side interface
void configureStaticIp6(const std::string &jailSideIface,
    const std::string &ip6, int jid,
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
