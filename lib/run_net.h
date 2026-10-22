// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

#include "util.h"
#include "spec.h"

#include <string>
#include <vector>
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
// 1.1.39: privops-aware interface destroy (teardown_iface verb; warn-only
// on failure). Used for epair halves and the auto-created bridge.
void teardownIface(const std::string &ifname);
// 1.1.39: privops-aware ipfw (args without the leading /sbin/ipfw).
void ipfwExec(const std::vector<std::string> &args, const std::string &what);

// 0.8.32: epairNumToIp moved into anon namespace in run_net.cpp —
// only called from within the file; no external callers in lib/,
// daemon/, tests/, or hub/. Header declaration was redundant.

// Set up ipfw NAT + filter rules for a container, returns cleanup callback.
// fwSlot is allocated from Ctx::FwSlots.
// ipv6Addr / ipv6Iface: jail-side IPv6 address and outbound interface
// (pass empty strings to skip IPv6 rules).
// sharedMode (1.1.57): 0 = legacy root mode — the shared outbound NAT
// instance + rule and net.inet.ip.forwarding are refcounted through
// Ctx::FwUsers in /var/run/crate; 1 = rootless, this caller is the FIRST
// user (crated said so through acquire_fw_lease) and creates the shared
// NAT instance + rule; 2 = rootless, not the first — skip them. In modes
// 1/2 the teardown never touches FwUsers or the sysctl: the daemon
// restores forwarding and the caller removes the common rule when
// release_fw_lease reports it was the last user.
RunAtEnd setupFirewallRules(const Spec &spec, const EpairInfo &epair,
                            const GatewayInfo &gw, unsigned fwSlot,
                            const std::string &nameserverIp,
                            int origIpForwarding, bool logProgress,
                            const std::string &ipv6Addr = {},
                            const std::string &ipv6Iface = {},
                            int sharedMode = 0);

// 1.1.57: remove the shared outbound NAT rule (the last rootless NAT user
// does this after release_fw_lease says fwd4_users == 0).
void removeCommonOutRule();

// 1.1.57: privops-aware `ifconfig <iface> inet6 <addr> prefixlen <n>`.
void setInet6AddrPrivopsOrLocal(const std::string &iface, const std::string &addr,
                                int prefixLen);

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
