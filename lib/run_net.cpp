// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "run_net.h"
#include "spec.h"
#include "net.h"
#include "ctx.h"
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
static const unsigned fwSlotSize = 10;
static const unsigned fwRuleRangeInBase = 10000;
static const unsigned fwRuleRangeOutBase = 50000;

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

  // create networking interface
  info.ifaceA = Util::stripTrailingSpace(
    Util::execCommandGetOutput({CRATE_PATH_IFCONFIG, "epair", "create"}, "create the jail epair"));
  info.ifaceB = STR(info.ifaceA.substr(0, info.ifaceA.size()-1) << "b");
  info.num = std::stoul(info.ifaceA.substr(5/*skip epair*/, info.ifaceA.size()-5-1));

  info.ipA = epairNumToIp(info.num, 0);
  info.ipB = epairNumToIp(info.num, 1);

  // disable checksum offload on epair interfaces to work around FreeBSD 15.0 bug
  // where packets between jails/host get dropped due to uncomputed checksums
  Util::execCommand({CRATE_PATH_IFCONFIG, info.ifaceA, "-txcsum", "-txcsum6"},
    "disable checksum offload on epair (host side)");
  Util::execCommand({CRATE_PATH_IFCONFIG, info.ifaceB, "-txcsum", "-txcsum6"},
    "disable checksum offload on epair (jail side)");

  // transfer the interface into jail
  Util::execCommand({CRATE_PATH_IFCONFIG, info.ifaceB, "vnet", jidStr},
    "transfer the network interface into jail");

  // set the IP addresses on the jail epair
  execInJail({CRATE_PATH_IFCONFIG, info.ifaceB, "inet", info.ipB, "netmask", "0xfffffffe"},
    "set up IP jail epair addresses");
  Util::execCommand({CRATE_PATH_IFCONFIG, info.ifaceA, "inet", info.ipA, "netmask", "0xfffffffe"},
    "set up IP jail epair addresses");

  // set default route in jail
  execInJail({CRATE_PATH_ROUTE, "add", "default", info.ipA}, "set default route in jail");

  return info;
}

void destroyEpair(const std::string &ifaceA) {
  Util::execCommand({CRATE_PATH_IFCONFIG, ifaceA, "destroy"},
    CSTR("destroy the jail epair (" << ifaceA << ")"));
}

RunAtEnd setupFirewallRules(const Spec &spec, const EpairInfo &epair,
                            const GatewayInfo &gw, unsigned fwSlot,
                            const std::string &nameserverIp,
                            int origIpForwarding, bool logProgress) {
  auto optionNet = spec.optionNet();
  if (!optionNet)
    return RunAtEnd();

  // exec-based ipfw wrapper: no shell, argv array passed directly
  auto execFW = [](const std::vector<std::string> &fwargs) {
    auto argv = std::vector<std::string>{CRATE_PATH_IPFW, "-q"};
    argv.insert(argv.end(), fwargs.begin(), fwargs.end());
    Util::execCommand(argv, "firewall rule");
  };

  auto fwRuleInNo  = fwRuleRangeInBase + fwSlot * fwSlotSize + 1;
  auto fwNatInNo = fwRuleInNo;
  auto fwNatOutCommonNo = fwRuleRangeOutBase;
  auto fwRuleOutCommonNo = fwRuleRangeOutBase;
  auto fwRuleOutNo = fwRuleRangeOutBase + fwSlot * fwSlotSize + 1;

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

  // cleanup callback
  return RunAtEnd([fwRuleInNo, fwRuleOutNo, fwRuleOutCommonNo, optionNet, origIpForwarding, logProgress]() {
    auto ruleInS  = std::to_string(fwRuleInNo);
    auto ruleOutS = std::to_string(fwRuleOutNo);
    auto ruleOutCommonS = std::to_string(fwRuleOutCommonNo);
    if (optionNet->allowInbound())
      Util::execCommand({CRATE_PATH_IPFW, "delete", ruleInS}, "destroy firewall rule");
    if (optionNet->allowOutbound()) {
      Util::execCommand({CRATE_PATH_IPFW, "delete", ruleOutS}, "destroy firewall rule");
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

RunAtEnd setupPfAnchor(const Spec &spec, const EpairInfo &epair,
                       const std::string &jailXname, bool logProgress) {
  if (!spec.firewallPolicy)
    return RunAtEnd();

  auto anchorName = STR("crate/" << jailXname);
  std::ostringstream pfRules;

  // Block IP ranges
  for (auto &cidr : spec.firewallPolicy->blockIp)
    pfRules << "block drop quick from " << epair.ipB << " to " << cidr << std::endl;
  // Allow specific TCP ports
  for (auto port : spec.firewallPolicy->allowTcp)
    pfRules << "pass out quick proto tcp from " << epair.ipB << " to any port " << port << std::endl;
  // Allow specific UDP ports
  for (auto port : spec.firewallPolicy->allowUdp)
    pfRules << "pass out quick proto udp from " << epair.ipB << " to any port " << port << std::endl;
  // Default policy
  if (spec.firewallPolicy->defaultPolicy == "block")
    pfRules << "block drop all" << std::endl;
  else
    pfRules << "pass all" << std::endl;

  // Load rules into pf anchor
  auto tmpRules = STR("/tmp/crate-pf-" << jailXname << ".conf");
  Util::Fs::writeFile(pfRules.str(), tmpRules);
  Util::execCommand({CRATE_PATH_PFCTL, "-a", anchorName, "-f", tmpRules}, "load pf anchor rules");
  Util::Fs::unlink(tmpRules);

  if (logProgress)
    std::cerr << rang::fg::gray << "pf anchor '" << anchorName << "' loaded" << rang::style::reset << std::endl;

  return RunAtEnd([anchorName, logProgress]() {
    if (logProgress)
      std::cerr << rang::fg::gray << "flushing pf anchor '" << anchorName << "'" << rang::style::reset << std::endl;
    Util::execCommand({CRATE_PATH_PFCTL, "-a", anchorName, "-F", "all"}, "flush pf anchor");
  });
}

}
