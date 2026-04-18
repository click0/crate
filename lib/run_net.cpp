// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "run_net.h"
#include "spec.h"
#include "net.h"
#include "ctx.h"
#include "ifconfig_ops.h"
#include "netgraph_ops.h"
#include "pfctl_ops.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#define ERR(msg...) ERR2("networking", msg)

// ipfw rule number layout (§18): dynamically assigned via FwSlots.
// Each crate gets a unique slot; rule numbers are: base + slot*slotSize + offset.
// IN rules use range 10000-29999, OUT rules use range 50000-64999.
// Override via environment: CRATE_IPFW_RULE_BASE_IN, CRATE_IPFW_RULE_BASE_OUT,
// CRATE_IPFW_SLOT_SIZE to avoid collisions with other jail managers.
static unsigned envOrDefault(const char *name, unsigned def) {
  auto *val = ::getenv(name);
  if (!val) return def;
  try { return Util::toUInt(val); } catch (...) { return def; }
}
static const unsigned fwSlotSize          = envOrDefault("CRATE_IPFW_SLOT_SIZE", 10);
static const unsigned fwRuleRangeInBase   = envOrDefault("CRATE_IPFW_RULE_BASE_IN", 10000);
static const unsigned fwRuleRangeOutBase  = envOrDefault("CRATE_IPFW_RULE_BASE_OUT", 50000);

namespace RunNet {

GatewayInfo detectGateway() {
  GatewayInfo gw;

  // determine host's gateway interface
  auto elts = Util::splitString(
    Util::execPipelineGetOutput(
      {{CRATE_PATH_NETSTAT, "-rn"}, {CRATE_PATH_GREP, "^default"}, {CRATE_PATH_SED, "s| *| |"}},
      "determine host's gateway interface"),
    " "
  );
  if (elts.size() != 4)
    ERR("Unable to determine host's gateway IP and interface");
  elts[3] = Util::stripTrailingSpace(elts[3]);
  gw.iface = elts[3];

  // determine host's gateway interface IP and network
  auto ipv4 = Net::getIfaceIp4Addresses(gw.iface);
  if (ipv4.empty())
    ERR("Failed to determine host's gateway interface IP: no IPv4 addresses found")
  gw.hostIP  = std::get<0>(ipv4[0]);
  gw.hostLAN = std::get<2>(ipv4[0]);

  return gw;
}

std::string epairNumToIp(unsigned epairNum, unsigned ipIdx) {
  // IP allocation (§19): uses 10.0.0.0/8 private address space for container networking.
  // Each container pair (host-side + jail-side) needs 2 IPs from a /31 subnet.
  // Starting offset 100 avoids .0 (network) and .1 (common gateway).
  // Maximum concurrent containers: (2^24 - 100) / 2 = ~8,388,558.
  unsigned ip = 100 + 2*epairNum + ipIdx;
  if (ip >= (1u << 24))
    ERR("epair number " << epairNum << " exceeds 10.0.0.0/8 address space capacity")
  unsigned ip1 = ip & 0xFF;
  unsigned ip2 = (ip >> 8) & 0xFF;
  unsigned ip3 = (ip >> 16) & 0xFF;
  return STR("10." << ip3 << "." << ip2 << "." << ip1);
}

EpairInfo createEpair(int jid, const std::string &jidStr,
                      const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail) {
  EpairInfo info;

  // set the lo0 IP address (lo0 is always automatically present in vnet jails)
  execInJail({CRATE_PATH_IFCONFIG, "lo0", "inet", "127.0.0.1"}, "set up the lo0 interface in jail");

  // create networking interface (uses libifconfig with shell fallback)
  auto epairPair = IfconfigOps::createEpair();
  info.ifaceA = epairPair.first;
  info.ifaceB = epairPair.second;
  info.num = Util::toUInt(info.ifaceA.substr(5/*skip epair*/, info.ifaceA.size()-5-1));

  info.ipA = epairNumToIp(info.num, 0);
  info.ipB = epairNumToIp(info.num, 1);

  // disable checksum offload on epair interfaces to work around FreeBSD 15.0 bug
  IfconfigOps::disableOffload(info.ifaceA);
  IfconfigOps::disableOffload(info.ifaceB);

  // transfer the interface into jail
  IfconfigOps::moveToVnet(info.ifaceB, jid);

  // set the IP addresses on the jail epair
  execInJail({CRATE_PATH_IFCONFIG, info.ifaceB, "inet", info.ipB, "netmask", "0xfffffffe"},
    "set up IP jail epair addresses");
  IfconfigOps::setInetAddr(info.ifaceA, info.ipA, 31);

  // set default route in jail
  execInJail({CRATE_PATH_ROUTE, "add", "default", info.ipA}, "set default route in jail");

  return info;
}

void destroyEpair(const std::string &ifaceA) {
  IfconfigOps::destroyInterface(ifaceA);
}

RunAtEnd setupFirewallRules(const Spec &spec, const EpairInfo &epair,
                            const GatewayInfo &gw, unsigned fwSlot,
                            const std::string &nameserverIp,
                            int origIpForwarding, bool logProgress,
                            const std::string &ipv6Addr,
                            const std::string &ipv6Iface) {
  auto optionNet = spec.optionNet();
  if (!optionNet)
    return RunAtEnd();

  // exec-based ipfw wrapper: no shell, argv array passed directly
  auto execFW = [](const std::vector<std::string> &fwargs) {
    auto argv = std::vector<std::string>{CRATE_PATH_IPFW, "-q"};
    argv.insert(argv.end(), fwargs.begin(), fwargs.end());
    Util::execCommand(argv, "firewall rule");
  };

  bool hasV6 = !ipv6Addr.empty();
  auto fwRuleInNo  = fwRuleRangeInBase + fwSlot * fwSlotSize + 1;
  auto fwNatInNo = fwRuleInNo;
  auto fwNatOutCommonNo = fwRuleRangeOutBase;
  auto fwRuleOutCommonNo = fwRuleRangeOutBase;
  auto fwRuleOutNo = fwRuleRangeOutBase + fwSlot * fwSlotSize + 1;
  auto fwRule6InNo = fwRuleRangeInBase + fwSlot * fwSlotSize + 2;

  auto ruleInS  = std::to_string(fwRuleInNo);
  auto natInS   = std::to_string(fwNatInNo);
  auto ruleOutS = std::to_string(fwRuleOutNo);
  auto ruleOutCommonS = std::to_string(fwRuleOutCommonNo);
  auto natOutCommonS  = std::to_string(fwNatOutCommonNo);

  // IN rules for this epair
  if (optionNet->allowInbound()) {
    auto rangeToStr = [](const Spec::NetOptDetails::PortRange &range) {
      return range.first == range.second ? STR(range.first) : STR(range.first << "-" << range.second);
    };
    // build nat config argv incrementally
    std::vector<std::string> natConfig = {"nat", natInS, "config"};
    for (auto &rangePair : optionNet->inboundPortsTcp) {
      natConfig.insert(natConfig.end(), {"redirect_port", "tcp",
        epair.ipB + ":" + rangeToStr(rangePair.second),
        gw.hostIP + ":" + rangeToStr(rangePair.first)});
    }
    for (auto &rangePair : optionNet->inboundPortsUdp) {
      natConfig.insert(natConfig.end(), {"redirect_port", "udp",
        epair.ipB + ":" + rangeToStr(rangePair.second),
        gw.hostIP + ":" + rangeToStr(rangePair.first)});
    }
    execFW(natConfig);
    // create firewall rules: one per port range
    for (auto &rangePair : optionNet->inboundPortsTcp) {
      execFW({"add", ruleInS, "nat", natInS, "tcp", "from", "any", "to", gw.hostIP, rangeToStr(rangePair.first), "in", "recv", gw.iface});
      execFW({"add", ruleInS, "nat", natInS, "tcp", "from", epair.ipB, rangeToStr(rangePair.second), "to", "any", "out", "xmit", gw.iface});
    }
    for (auto &rangePair : optionNet->inboundPortsUdp) {
      execFW({"add", ruleInS, "nat", natInS, "udp", "from", "any", "to", gw.hostIP, rangeToStr(rangePair.first), "in", "recv", gw.iface});
      execFW({"add", ruleInS, "nat", natInS, "udp", "from", epair.ipB, rangeToStr(rangePair.second), "to", "any", "out", "xmit", gw.iface});
    }

    // IPv6 inbound: no NAT, use ipfw fwd to forward directly to jail IPv6 addr.
    // IPv6 global addresses are routable, so we only need a forward rule.
    if (hasV6) {
      auto fwRule6InNo = fwRuleRangeInBase + fwSlot * fwSlotSize + 2;
      auto rule6InS = std::to_string(fwRule6InNo);
      for (auto &rangePair : optionNet->inboundPortsTcp) {
        execFW({"add", rule6InS, "fwd", ipv6Addr + "," + rangeToStr(rangePair.second),
                "tcp", "from", "any", "to", "me6", rangeToStr(rangePair.first), "in"});
      }
      for (auto &rangePair : optionNet->inboundPortsUdp) {
        execFW({"add", rule6InS, "fwd", ipv6Addr + "," + rangeToStr(rangePair.second),
                "udp", "from", "any", "to", "me6", rangeToStr(rangePair.first), "in"});
      }
    }
  }

  // OUT common rules
  if (optionNet->allowOutbound()) {
    std::unique_ptr<Ctx::FwUsers> fwUsers(Ctx::FwUsers::lock());
    if (fwUsers->isEmpty()) {
      execFW({"nat", natOutCommonS, "config", "ip", gw.hostIP});
      execFW({"add", ruleOutCommonS, "nat", natOutCommonS, "all", "from", "any", "to", gw.hostIP, "in", "recv", gw.iface});
    }
    fwUsers->add(::getpid());
    fwUsers->unlock();
  }

  // OUT per-epair rules: 1. whitewashes, 2. bans, 3. nats
  if (optionNet->allowOutbound()) {
    if (optionNet->outboundDns) {
      execFW({"add", ruleOutS, "nat", natOutCommonS, "udp", "from", epair.ipB, "to", nameserverIp, "53", "out", "xmit", gw.iface});
      execFW({"add", ruleOutS, "allow", "udp", "from", epair.ipB, "to", nameserverIp, "53"});
    }
    execFW({"add", ruleOutS, "deny", "udp", "from", epair.ipB, "to", "any", "53"});
    if (!optionNet->outboundHost)
      execFW({"add", ruleOutS, "deny", "ip", "from", epair.ipB, "to", "me"});
    if (!optionNet->outboundLan)
      execFW({"add", ruleOutS, "deny", "ip", "from", epair.ipB, "to", gw.hostLAN});
    execFW({"add", ruleOutS, "nat", natOutCommonS, "all", "from", epair.ipB, "to", "any", "out", "xmit", gw.iface});
  }

  // IPv6 outbound rules (no NAT — IPv6 uses global addresses)
  unsigned fwRule6OutNo = 0;
  if (hasV6 && optionNet->allowOutbound()) {
    fwRule6OutNo = fwRuleRangeOutBase + fwSlot * fwSlotSize + 2;
    auto rule6S = std::to_string(fwRule6OutNo);
    auto v6Iface = ipv6Iface.empty() ? gw.iface : ipv6Iface;
    if (optionNet->outboundDns)
      execFW({"add", rule6S, "allow", "udp", "from", ipv6Addr, "to", "any", "53"});
    execFW({"add", rule6S, "deny", "udp", "from", ipv6Addr, "to", "any", "53"});
    if (!optionNet->outboundHost)
      execFW({"add", rule6S, "deny", "ip6", "from", ipv6Addr, "to", "me6"});
    execFW({"add", rule6S, "allow", "ip6", "from", ipv6Addr, "to", "any", "out", "xmit", v6Iface});
    execFW({"add", rule6S, "allow", "ip6", "from", "any", "to", ipv6Addr, "in", "recv", v6Iface});
  }

  // cleanup callback
  return RunAtEnd([fwRuleInNo, fwRule6InNo, fwRuleOutNo, fwRuleOutCommonNo, fwRule6OutNo, hasV6, optionNet, origIpForwarding, logProgress]() {
    auto ruleInS  = std::to_string(fwRuleInNo);
    auto ruleOutS = std::to_string(fwRuleOutNo);
    auto ruleOutCommonS = std::to_string(fwRuleOutCommonNo);
    if (optionNet->allowInbound()) {
      Util::execCommand({CRATE_PATH_IPFW, "delete", ruleInS}, "destroy firewall rule");
      if (hasV6) {
        try {
          Util::execCommand({CRATE_PATH_IPFW, "delete", std::to_string(fwRule6InNo)}, "destroy IPv6 inbound firewall rule");
        } catch (const std::exception &e) {
          WARN("failed to delete IPv6 inbound rule " << fwRule6InNo << ": " << e.what())
        }
      }
    }
    if (optionNet->allowOutbound()) {
      Util::execCommand({CRATE_PATH_IPFW, "delete", ruleOutS}, "destroy firewall rule");
      if (hasV6 && fwRule6OutNo > 0) {
        try {
          Util::execCommand({CRATE_PATH_IPFW, "delete", std::to_string(fwRule6OutNo)}, "destroy IPv6 firewall rule");
        } catch (const std::exception &e) {
          WARN("failed to delete IPv6 firewall rule " << fwRule6OutNo << ": " << e.what())
        }
      }
      std::unique_ptr<Ctx::FwUsers> fwUsers(Ctx::FwUsers::lock());
      fwUsers->del(::getpid());
      if (fwUsers->isEmpty()) {
        Util::execCommand({CRATE_PATH_IPFW, "delete", ruleOutCommonS}, "destroy firewall rule");
        if (origIpForwarding == 0) {
          if (logProgress)
            std::cerr << rang::fg::gray << "restoring net.inet.ip.forwarding to 0" << rang::style::reset << std::endl;
          Util::setSysctlInt("net.inet.ip.forwarding", 0);
        }
      }
      fwUsers->unlock();
    }
  });
}

//
// Passthrough mode
//

PassthroughInfo passthroughInterface(int jid, const std::string &jidStr,
    const std::string &iface,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail) {
  PassthroughInfo info;
  info.iface = iface;

  // set the lo0 IP address
  execInJail({CRATE_PATH_IFCONFIG, "lo0", "inet", "127.0.0.1"}, "set up the lo0 interface in jail");

  // pass the physical interface directly into the jail
  IfconfigOps::moveToVnet(iface, jid);

  return info;
}

void reclaimPassthroughInterface(const PassthroughInfo &info,
    const std::string &jailName) {
  // Reclaim the interface from the jail back to the host.
  // Uses -vnet with the jail name. MUST be called before jail destruction.
  Util::execCommand({CRATE_PATH_IFCONFIG, info.iface, "-vnet", jailName},
    CSTR("reclaim interface " << info.iface << " from jail " << jailName));
}

//
// Bridge mode
//

void ensureBridgeModule() {
  Util::ensureKernelModuleIsLoaded("if_bridge");
}

void ensureNetgraphModules() {
  Util::ensureKernelModuleIsLoaded("ng_ether");
  Util::ensureKernelModuleIsLoaded("ng_bridge");
  Util::ensureKernelModuleIsLoaded("ng_eiface");
}

NetgraphInfo createNetgraphInterface(int jid, const std::string &jidStr,
    const std::string &physIface, const std::string &jailName,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail) {
  NetgraphInfo info;
  info.physIface = physIface;
  info.bridgeNode = STR("crate_br_" << jailName);

  // set the lo0 IP address
  execInJail({CRATE_PATH_IFCONFIG, "lo0", "inet", "127.0.0.1"}, "set up the lo0 interface in jail");

  // Create ng_bridge node attached to the physical interface's lower hook
  NetgraphOps::mkpeer(STR(physIface << ":"), "bridge", "lower", "link0");

  // Name the bridge node for easier management
  NetgraphOps::name(STR(physIface << ":lower"), info.bridgeNode);

  // Connect the upper hook of the physical interface to the bridge
  NetgraphOps::connect(STR(physIface << ":"), STR(info.bridgeNode << ":"), "upper", "link1");

  // Create an eiface for the jail
  NetgraphOps::mkpeer(STR(info.bridgeNode << ":"), "eiface", "link2", "ether");

  // Get the eiface name
  info.ngIface = NetgraphOps::show(STR(info.bridgeNode << ":link2"));
  // Parse the interface name from output (format: "Name: ngeth0  ...")
  auto namePos = info.ngIface.find("Name: ");
  if (namePos != std::string::npos) {
    info.ngIface = info.ngIface.substr(namePos + 6);
    auto spacePos = info.ngIface.find(' ');
    if (spacePos != std::string::npos)
      info.ngIface = info.ngIface.substr(0, spacePos);
  }

  // Move eiface into jail
  IfconfigOps::moveToVnet(info.ngIface, jid);

  return info;
}

void destroyNetgraphInterface(const NetgraphInfo &info) {
  // Shutdown the bridge node — this cleans up all connected peers
  NetgraphOps::shutdown(STR(info.bridgeNode << ":"));
}

BridgeInfo createBridgeEpair(int jid, const std::string &jidStr,
    const std::string &bridgeIface,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail) {
  BridgeInfo info;
  info.bridgeIface = bridgeIface;

  // set the lo0 IP address
  execInJail({CRATE_PATH_IFCONFIG, "lo0", "inet", "127.0.0.1"}, "set up the lo0 interface in jail");

  // create epair
  auto epairPair = IfconfigOps::createEpair();
  info.ifaceA = epairPair.first;
  info.ifaceB = epairPair.second;
  info.num = Util::toUInt(info.ifaceA.substr(5, info.ifaceA.size()-5-1));

  // disable checksum offload (FreeBSD 15 workaround)
  IfconfigOps::disableOffload(info.ifaceA);
  IfconfigOps::disableOffload(info.ifaceB);

  // bring host-side up and add to bridge
  IfconfigOps::setUp(info.ifaceA);
  IfconfigOps::bridgeAddMember(bridgeIface, info.ifaceA);

  // move jail-side into jail
  IfconfigOps::moveToVnet(info.ifaceB, jid);

  return info;
}

void destroyBridgeEpair(const BridgeInfo &info) {
  // remove from bridge first, then destroy
  IfconfigOps::bridgeDelMember(info.bridgeIface, info.ifaceA);
  IfconfigOps::destroyInterface(info.ifaceA);
}

//
// IP configuration for bridge/passthrough/netgraph modes
//

void configureDhcp(const std::string &jailSideIface,
    const std::string &jailPath, int jid, const std::string &jidStr,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail) {
  // Write SYNCDHCP config to jail's rc.conf
  Util::Fs::appendFile(
    STR("ifconfig_" << jailSideIface << "=\"SYNCDHCP\"" << std::endl),
    STR(jailPath << "/etc/rc.conf"));

  // Bring interface up
  execInJail({CRATE_PATH_IFCONFIG, jailSideIface, "up"}, "bring up jail interface for DHCP");

  // Run dhclient with timeout (SYNCDHCP semantics: wait for lease)
  execInJail({CRATE_PATH_DHCLIENT, "-T", "10", jailSideIface}, "acquire DHCP lease");
}

void configureStaticIp(const std::string &jailSideIface,
    const std::string &ip, const std::string &gateway, int jid,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail) {
  // Parse IP and netmask from CIDR notation (e.g. "192.168.1.50/24")
  auto slashPos = ip.find('/');
  std::string addr, netmask;
  if (slashPos != std::string::npos) {
    addr = ip.substr(0, slashPos);
    auto prefixLen = Util::toUInt(ip.substr(slashPos + 1));
    // Convert prefix length to hex netmask
    uint32_t mask = prefixLen > 0 ? ~((1u << (32 - prefixLen)) - 1) : 0;
    netmask = STR("0x" << std::hex << mask);
  } else {
    addr = ip;
    netmask = "0xffffff00"; // default /24
  }

  execInJail({CRATE_PATH_IFCONFIG, jailSideIface, "inet", addr, "netmask", netmask},
    "configure static IP on jail interface");

  if (!gateway.empty())
    execInJail({CRATE_PATH_ROUTE, "add", "default", gateway}, "set default route in jail");
}

//
// IPv6 SLAAC configuration
//

void configureSlaac(const std::string &jailSideIface,
    const std::string &jailPath, int jid, const std::string &jidStr,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail) {
  // Write SLAAC config to jail's rc.conf
  Util::Fs::appendFile(
    STR("ifconfig_" << jailSideIface << "_ipv6=\"inet6 -ifdisabled accept_rtadv\"" << std::endl),
    STR(jailPath << "/etc/rc.conf"));

  // Enable IPv6 and accept router advertisements on the interface
  execInJail({CRATE_PATH_IFCONFIG, jailSideIface, "inet6", "-ifdisabled", "accept_rtadv"},
    "enable IPv6 SLAAC on jail interface");

  // Solicit router advertisements (one-shot)
  execInJail({CRATE_PATH_RTSOL, jailSideIface}, "solicit IPv6 router advertisements");
}

//
// Static IPv6 configuration
//

void configureStaticIp6(const std::string &jailSideIface,
    const std::string &ip6, int jid,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail) {
  // Parse address and prefix length from CIDR notation (e.g. "fd00::50/64")
  auto slashPos = ip6.find('/');
  std::string addr;
  std::string prefixLen = "64"; // default
  if (slashPos != std::string::npos) {
    addr = ip6.substr(0, slashPos);
    prefixLen = ip6.substr(slashPos + 1);
  } else {
    addr = ip6;
  }

  execInJail({CRATE_PATH_IFCONFIG, jailSideIface, "inet6", addr, "prefixlen", prefixLen},
    "configure static IPv6 on jail interface");
}

//
// Static MAC address generation (inspired by BastilleBSD generate_static_mac)
//

std::pair<std::string,std::string> generateStaticMac(
    const std::string &jailName, const std::string &ifaceName) {
  // OUI prefix: 58:9c:fc (locally administered, FreeBSD convention)
  auto hash = Util::sha256hex(ifaceName + jailName);
  // Take 5 hex chars from the hash for the last 2.5 octets
  auto suffix = hash.substr(0, 5);
  // Build base MAC: 58:9c:fc:XX:XX:X
  auto base = STR("58:9c:fc:"
    << suffix[0] << suffix[1] << ":"
    << suffix[2] << suffix[3] << ":"
    << suffix[4]);
  return {base + "a", base + "b"};
}

void setMacAddress(const std::string &iface, const std::string &mac) {
  IfconfigOps::setMacAddr(iface, mac);
}

//
// VLAN interface creation inside jail
//

void createVlanInJail(int jid, const std::string &parentIface, int vlanId,
    const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail) {
  Util::ensureKernelModuleIsLoaded("if_vlan");
  auto vlanIface = STR("vlan" << vlanId);
  execInJail({CRATE_PATH_IFCONFIG, vlanIface, "create"},
    CSTR("create VLAN interface " << vlanIface));
  execInJail({CRATE_PATH_IFCONFIG, vlanIface, "vlan", std::to_string(vlanId), "vlandev", parentIface},
    CSTR("configure VLAN " << vlanId << " on " << parentIface));
  execInJail({CRATE_PATH_IFCONFIG, vlanIface, "up"},
    CSTR("bring up " << vlanIface));
}

}
