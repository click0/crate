// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include <list>
#include <set>
#include <sstream>
#include <string>

#include "spec_pure.h"
#include "spec.h"
#include "config.h"
#include "wireguard_runtime_pure.h"
#include "ipsec_runtime_pure.h"
#include "lst-all-script-sections.h"   // generated: defines allScriptSections

#include "util.h"   // Util::toUInt
#include "err.h"
#include "netaddr_pure.h"   // 1.1.44: isV4 / isV6
#include "mounts_pure.h"    // 1.1.63: tmpfs / etc/keep
#include "run_pure.h"       // 1.1.64: run/user
#include "privops_pure.h"   // 1.1.44: validateIpv4Cidr / validateIpv6Cidr

namespace SpecPure {

PortRange parsePortRange(const std::string &str) {
  auto hyphen = str.find('-');
  PortRange r = hyphen == std::string::npos
    ? PortRange(SpecPure::parsePort(str, "port"), SpecPure::parsePort(str, "port"))
    : PortRange(SpecPure::parsePort(str.substr(0, hyphen), "port range start"),
                SpecPure::parsePort(str.substr(hyphen + 1), "port range end"));
  if (r.first > r.second)
    ERR2("spec", "port range '" << str << "' is reversed (start > end)")
  return r;
}

std::string substituteVars(const std::string &input,
                           const std::map<std::string, std::string> &vars) {
  if (vars.empty())
    return input;
  std::string result = input;
  for (auto &kv : vars) {
    std::string token = "${" + kv.first + "}";
    size_t pos = 0;
    while ((pos = result.find(token, pos)) != std::string::npos) {
      result.replace(pos, token.length(), kv.second);
      pos += kv.second.length();
    }
  }
  return result;
}

std::string validateTopLevelNetwork(const std::string &v) {
  // "auto" is the only currently-supported value. Reserved for
  // future: a bridge name (network: bridge0), "host" (host network
  // namespace), "none" (no network at all). Be strict on input now
  // so future expansions stay backwards-compatible.
  if (v == "auto") return "";
  if (v.empty())
    return "top-level 'network:' must be a string (currently only 'auto' is supported)";
  return "top-level 'network: " + v
       + "' is not supported (the only currently-accepted value is 'auto'; "
         "for richer config use 'options.net' instead)";
}

}

// ===================================================================
// Pure method definitions for Spec / Spec::NetOptDetails / Spec::OptDetails.
// Originally lived in lib/spec.cpp; moved here so unit tests can link
// against them without dragging in yaml-cpp etc.
// ===================================================================

Spec::OptDetails::~OptDetails() {}

Spec::NetOptDetails::NetOptDetails()
: outboundWan(false),
  outboundLan(false),
  outboundHost(false),
  outboundDns(false),
  ipv6(false)
{ }

bool Spec::NetOptDetails::allowOutbound() const {
  return outboundWan || outboundLan || outboundHost || outboundDns;
}

bool Spec::NetOptDetails::allowInbound() const {
  return !inboundPortsTcp.empty() || !inboundPortsUdp.empty();
}

bool Spec::NetOptDetails::isNatMode() const {
  return mode == Mode::Nat;
}

bool Spec::NetOptDetails::needsIpfw() const {
  return mode == Mode::Nat;
}

bool Spec::NetOptDetails::needsDhcp() const {
  return ipMode == IpMode::Dhcp;
}

bool Spec::optionExists(const char* opt) const {
  return options.find(opt) != options.end();
}

template<class OptDetailsClass>
const OptDetailsClass* Spec::getOptionDetails(const char *opt) const {
  auto it = options.find(opt);
  if (it == options.end())
    return nullptr;
  return static_cast<const OptDetailsClass*>(it->second.get());
}

template<class OptDetailsClass>
OptDetailsClass* Spec::getOptionDetailsWr(const char *opt) const {
  auto it = options.find(opt);
  if (it == options.end())
    return nullptr;
  return static_cast<OptDetailsClass*>(it->second.get());
}

const Spec::NetOptDetails* Spec::optionNet() const {
  return getOptionDetails<Spec::NetOptDetails>("net");
}

Spec::NetOptDetails* Spec::optionNetWr() const {
  return getOptionDetailsWr<Spec::NetOptDetails>("net");
}

const Spec::TorOptDetails* Spec::optionTor() const {
  return getOptionDetails<Spec::TorOptDetails>("tor");
}

const Spec::WireguardOptDetails* Spec::optionWireguard() const {
  return getOptionDetails<Spec::WireguardOptDetails>("wireguard");
}

const Spec::IpsecOptDetails* Spec::optionIpsec() const {
  return getOptionDetails<Spec::IpsecOptDetails>("ipsec");
}

std::shared_ptr<Spec::NetOptDetails> Spec::NetOptDetails::createDefault() {
  // default "net" options allow all outbound and no inbound
  auto d = std::make_shared<NetOptDetails>();
  d->outboundWan  = true;
  d->outboundLan  = true;
  d->outboundHost = true;
  d->outboundDns  = true;
  return d;
}

Spec::TorOptDetails::TorOptDetails()
: controlPort(false)
{ }

std::shared_ptr<Spec::TorOptDetails> Spec::TorOptDetails::createDefault() {
  return std::make_shared<TorOptDetails>();
}

Spec::WireguardOptDetails::WireguardOptDetails() = default;

std::shared_ptr<Spec::WireguardOptDetails> Spec::WireguardOptDetails::createDefault() {
  return std::make_shared<WireguardOptDetails>();
}

Spec::IpsecOptDetails::IpsecOptDetails() = default;

std::shared_ptr<Spec::IpsecOptDetails> Spec::IpsecOptDetails::createDefault() {
  return std::make_shared<IpsecOptDetails>();
}

// ===================================================================
// Allowed-options set (also referenced by lib/spec.cpp's parser).
// Keep in sync with the list in spec.cpp.
// ===================================================================
namespace {

#define ERR(msg...) ERR2("crate spec validate", msg)

static const std::list<std::string> allOptionsLst = {
  "x11", "net", "ssl-certs", "tor", "video", "gl", "wireguard", "ipsec",
  "no-rm-static-libs", "dbg-ktrace"
};
static const std::set<std::string> allOptionsSet(
  std::begin(allOptionsLst), std::end(allOptionsLst));

}

void Spec::validate() const {
  auto isFullPath = [](const std::string &path) {
    return !path.empty() && path[0] == '/';
  };

  // must have something to run
  if (runCmdExecutable.empty() && runServices.empty() && !optionExists("tor"))
    ERR("crate has to have either the executable to run, some services to run, or both, it can't have nothing to do")

  // must be no duplicate local package overrides
  if (!pkgLocalOverride.empty()) {
    std::map<std::string, std::string> pkgs;
    for (auto &lo : pkgLocalOverride) {
      if (pkgs.find(lo.first) != pkgs.end())
        ERR("duplicate local override packages: " << lo.first << "->" << pkgs[lo.first] << " and " << lo.first << "->" << lo.second)
      pkgs[lo.first] = lo.second;
    }
  }

  // executable must have full path
  if (!runCmdExecutable.empty())
    if (!isFullPath(runCmdExecutable))
      ERR("the executable path has to be a full path, executable=" << runCmdExecutable)

  // 1.1.64: run/user
  if (auto e = RunPure::validateRunUser(runUser); !e.empty())
    ERR(e)

  // shared directories must be full paths
  for (auto &dirShare : dirsShare)
    if (!isFullPath(Util::pathSubstituteVarsInPath(dirShare.jail)) || !isFullPath(Util::pathSubstituteVarsInPath(dirShare.host)))
      ERR("the shared directory paths have to be a full paths, share=" << dirShare.jail << "->" << dirShare.host)

  // shared files must be full paths
  for (auto &fileShare : filesShare) {
    if (!isFullPath(Util::pathSubstituteVarsInPath(fileShare.jail)) || !isFullPath(Util::pathSubstituteVarsInPath(fileShare.host)))
      ERR("the shared directory paths have to be a full paths, share=" << fileShare.jail << "->" << fileShare.host)
    if (fileShare.readOnly)
      ERR("files/share: a file share cannot be read-only: " << fileShare.jail)
  }

  // 1.1.63: tmpfs mount points and etc/keep names (the parser checks
  // them too; a Spec built in code goes through here only)
  for (size_t i = 0; i < tmpfs.size(); i++) {
    if (auto e = MountsPure::validateTmpfsPath(tmpfs[i].path); !e.empty()) ERR("tmpfs: " << e)
    if (auto e = MountsPure::validateTmpfsSize(tmpfs[i].size); !e.empty()) ERR("tmpfs/" << tmpfs[i].path << ": " << e)
    for (size_t j = 0; j < i; j++)
      if (tmpfs[j].path == tmpfs[i].path) ERR("tmpfs: '" << tmpfs[i].path << "' is listed twice")
    for (auto &d : dirsShare)
      if (d.jail == tmpfs[i].path)
        ERR("tmpfs: '" << tmpfs[i].path << "' is also a dirs/share destination — the tmpfs would hide the share")
  }
  for (auto &n : etcKeep)
    if (auto e = MountsPure::validateEtcKeepName(n); !e.empty()) ERR(e)

  // pkg/add entries must be absolute paths to .txz package files on the host
  for (auto &p : pkgAdd)
    if (!isFullPath(Util::pathSubstituteVarsInPath(p)))
      ERR("pkg/add entries must be absolute paths to .txz package files: " << p)

  // options must be from the supported set
  for (auto &o : options)
    if (allOptionsSet.find(o.first) == allOptionsSet.end())
      ERR("the unknown option '" << o.first << "' was supplied")

  // script sections must be from the supported set
  for (auto &s : scripts)
    if (s.first.empty() || allScriptSections.find(s.first) == allScriptSections.end())
      ERR("the unknown script section '" << s.first << "' was supplied")

  // port ranges in net options must be consistent
  if (auto optNet = optionNet()) {
    for (auto pv : {&optNet->inboundPortsTcp, &optNet->inboundPortsUdp})
      for (auto &rangePair : *pv)
        if (rangePair.first.second - rangePair.first.first != rangePair.second.second - rangePair.second.first)
          ERR("port ranges have different spans:"
            << rangePair.first.first << "-" << rangePair.first.second
            << " and "
            << rangePair.second.first << "-" << rangePair.second.second)

    // validate named network references
    if (!optNet->networkName.empty()) {
      auto &cfg = Config::get();
      if (cfg.networks.find(optNet->networkName) == cfg.networks.end()) {
        std::ostringstream avail;
        for (auto &n : cfg.networks)
          avail << " " << n.first;
        ERR("options/net/network '" << optNet->networkName << "' not found in system config"
            << (cfg.networks.empty() ? "; no networks defined in crate.yml" : "; available:" + avail.str()))
      }
    }
    for (size_t i = 0; i < optNet->extraInterfaces.size(); i++) {
      auto &ex = optNet->extraInterfaces[i];
      if (!ex.networkName.empty()) {
        auto &cfg = Config::get();
        if (cfg.networks.find(ex.networkName) == cfg.networks.end())
          ERR("options/net/extra[" << i << "]/network '" << ex.networkName << "' not found in system config")
      }
    }

    // mode-specific validation
    using Mode = Spec::NetOptDetails::Mode;
    if (optNet->mode == Mode::Bridge && optNet->bridgeIface.empty())
      ERR("options/net/mode=bridge requires 'bridge' field (e.g. bridge: bridge0)")
    if (optNet->autoCreateBridge && optNet->mode != Mode::Bridge)
      ERR("options/net/auto_create_bridge: true is only meaningful in bridge mode")
    if (optNet->mode == Mode::Passthrough && optNet->passthroughIface.empty())
      ERR("options/net/mode=passthrough requires 'interface' field")
    if (optNet->mode == Mode::Netgraph && optNet->netgraphIface.empty())
      ERR("options/net/mode=netgraph requires 'interface' field")
    if (optNet->mode == Mode::Nat) {
      if (!optNet->bridgeIface.empty())
        ERR("options/net/bridge is only valid with mode=bridge")
      if (optNet->ipMode == Spec::NetOptDetails::IpMode::Dhcp)
        ERR("options/net/ip=dhcp is not valid with mode=nat (NAT uses automatic IP)")
      if (optNet->ipMode == Spec::NetOptDetails::IpMode::Static)
        ERR("options/net/ip with static address is not valid with mode=nat")
    }
    if (optNet->mode != Mode::Nat) {
      if (optNet->allowInbound())
        ERR("options/net/inbound-tcp/udp are only valid with mode=nat")
    }
    if (!optNet->gateway.empty() && optNet->ipMode != Spec::NetOptDetails::IpMode::Static)
      ERR("options/net/gateway is only valid with static IP")
    if (optNet->vlanId >= 0 && optNet->mode == Mode::Nat)
      ERR("options/net/vlan is only valid with bridge, passthrough, or netgraph mode")
    if (optNet->staticMac && optNet->mode == Mode::Nat)
      ERR("options/net/static-mac is only valid with bridge, passthrough, or netgraph mode")
    if (optNet->ip6Mode != Spec::NetOptDetails::Ip6Mode::None && optNet->mode == Mode::Nat)
      ERR("options/net/ip6 (slaac/static) is only valid with bridge, passthrough, or netgraph mode; use ipv6: true for NAT mode")
    if (optNet->ip6Mode == Spec::NetOptDetails::Ip6Mode::Static && optNet->staticIp6.empty())
      ERR("options/net/ip6 with static address requires an IPv6 address (e.g. fd00::50/64)")
    if (!optNet->extraInterfaces.empty() && optNet->mode == Mode::Nat)
      ERR("options/net/extra interfaces are only valid with bridge, passthrough, or netgraph primary mode")
    for (size_t i = 0; i < optNet->extraInterfaces.size(); i++) {
      auto &ex = optNet->extraInterfaces[i];
      if (ex.mode == Mode::Bridge && ex.bridgeIface.empty())
        ERR("options/net/extra[" << i << "]/mode=bridge requires 'bridge' field")
      if (ex.mode == Mode::Passthrough && ex.passthroughIface.empty())
        ERR("options/net/extra[" << i << "]/mode=passthrough requires 'interface' field")
      if (ex.mode == Mode::Netgraph && ex.netgraphIface.empty())
        ERR("options/net/extra[" << i << "]/mode=netgraph requires 'interface' field")
      if (ex.mode == Mode::Nat)
        ERR("options/net/extra[" << i << "]/mode=nat is not allowed for extra interfaces")
      if (!ex.gateway.empty() && ex.ipMode != Spec::NetOptDetails::IpMode::Static)
        ERR("options/net/extra[" << i << "]/gateway is only valid with static IP")
      if (ex.ip6Mode == Spec::NetOptDetails::Ip6Mode::Static && ex.staticIp6.empty())
        ERR("options/net/extra[" << i << "]/ip6 with static address requires an IPv6 address")
    }
  }

  // ZFS dataset names must be valid
  for (auto &ds : zfsDatasets)
    if (ds.empty() || ds[0] == '/' || ds.find("..") != std::string::npos)
      ERR("invalid ZFS dataset name: " << ds)

  // RCTL resource limit names must be valid
  {
    static const std::set<std::string> validLimits = {
      "cputime", "datasize", "stacksize", "coredumpsize", "memoryuse",
      "memorylocked", "maxproc", "openfiles", "vmemoryuse", "pseudoterminals",
      "swapuse", "nthr", "msgqqueued", "msgqsize", "nmsgq", "nsem",
      "nsemop", "nshm", "shmsize", "wallclock", "pcpu", "readbps",
      "writebps", "readiops", "writeiops"
    };
    for (auto &lim : limits)
      if (validLimits.find(lim.first) == validLimits.end())
        ERR("unknown resource limit: " << lim.first)
  }

  // encryption validation
  if (encrypted) {
    if (!encryptionMethod.empty() && encryptionMethod != "zfs")
      ERR("only 'zfs' encryption method is currently supported")
    if (!encryptionKeyformat.empty() && encryptionKeyformat != "passphrase"
        && encryptionKeyformat != "hex" && encryptionKeyformat != "raw")
      ERR("unsupported encryption keyformat: " << encryptionKeyformat)
    if (!encryptionCipher.empty() && encryptionCipher != "aes-256-gcm"
        && encryptionCipher != "aes-256-ccm" && encryptionCipher != "aes-128-gcm"
        && encryptionCipher != "aes-128-ccm")
      ERR("unsupported encryption cipher: " << encryptionCipher)
  }

  // enforce_statfs range
  if (enforceStatfs != -1 && (enforceStatfs < 0 || enforceStatfs > 2))
    ERR("security/enforce_statfs must be 0, 1, or 2")

  // COW validation
  if (cowOptions) {
    if (cowOptions->mode != "ephemeral" && cowOptions->mode != "persistent")
      ERR("cow/mode must be 'ephemeral' or 'persistent'")
    if (cowOptions->backend != "zfs" && cowOptions->backend != "unionfs")
      ERR("cow/backend must be 'zfs' or 'unionfs'")
  }

  // clipboard validation
  if (clipboardOptions) {
    if (clipboardOptions->mode != "isolated" && clipboardOptions->mode != "shared" && clipboardOptions->mode != "none")
      ERR("clipboard/mode must be 'isolated', 'shared', or 'none'")
  }

  // D-Bus validation
  if (dbusOptions) {
    if (!dbusOptions->systemBus && !dbusOptions->sessionBus)
      ERR("dbus section present but both system and session are disabled")
  }

  // managed services validation
  for (auto &ms : managedServices)
    if (ms.name.empty())
      ERR("managed service entry missing name")

  // socket proxy validation
  if (socketProxy) {
    for (auto &s : socketProxy->share)
      if (s.empty() || s[0] != '/')
        ERR("socket_proxy/share paths must be absolute: " << s)
    for (auto &p : socketProxy->proxy) {
      if (p.host.empty() || p.host[0] != '/')
        ERR("socket_proxy/proxy/host path must be absolute: " << p.host)
      if (p.jail.empty() || p.jail[0] != '/')
        ERR("socket_proxy/proxy/jail path must be absolute: " << p.jail)
    }
  }

  // firewall policy validation
  if (firewallPolicy) {
    for (auto port : firewallPolicy->allowTcp)
      if (port == 0 || port > 65535)
        ERR("firewall/allow-tcp port out of range: " << port)
    for (auto port : firewallPolicy->allowUdp)
      if (port == 0 || port > 65535)
        ERR("firewall/allow-udp port out of range: " << port)
  }

  // terminal validation
  if (terminalOptions) {
    if (terminalOptions->devfsRuleset != -1 && (terminalOptions->devfsRuleset < 0 || terminalOptions->devfsRuleset > 65535))
      ERR("terminal/devfs_ruleset must be 0-65535")
  }

  // wireguard option: a non-empty `config` path must be valid
  if (auto *wg = optionWireguard()) {
    if (!wg->configPath.empty()) {
      auto reason = WireguardRuntimePure::validateConfigPath(wg->configPath);
      if (!reason.empty())
        ERR("options/wireguard/config: " << reason)
    }
  }

  // ipsec option: a non-empty `conn` name must be valid (0.8.4)
  if (auto *ip = optionIpsec()) {
    if (!ip->connName.empty()) {
      auto reason = IpsecRuntimePure::validateConnName(ip->connName);
      if (!reason.empty())
        ERR("options/ipsec/conn: " << reason)
    }
  }

}

#undef ERR

// --- 1.1.44: options/net address validators ---

std::string SpecPure::validateStaticIp4(const std::string &v) {
  if (v.empty()) return "address is empty";
  if (v.find('/') == std::string::npos)
    return NetAddrPure::isV4(v) ? "" : "'" + v + "' is not an IPv4 address";
  // a.b.c.d/N — PrivOpsPure checks the octets and 0..32
  if (auto e = PrivOpsPure::validateIpv4Cidr(v); !e.empty()) return "'" + v + "': " + e;
  return "";
}

std::string SpecPure::validateStaticIp6(const std::string &v) {
  if (v.empty()) return "address is empty";
  if (v.find('/') == std::string::npos)
    return NetAddrPure::isV6(v) ? "" : "'" + v + "' is not an IPv6 address";
  if (auto e = PrivOpsPure::validateIpv6Cidr(v); !e.empty()) return "'" + v + "': " + e;
  return "";
}

std::string SpecPure::validateGateway4(const std::string &v) {
  if (v.empty()) return "gateway is empty";
  if (v.find('/') != std::string::npos) return "gateway must be a bare IPv4 address, not a CIDR";
  return NetAddrPure::isV4(v) ? "" : "'" + v + "' is not an IPv4 address";
}

// --- 1.1.46: bounded integers ---

int SpecPure::parseIntInRange(const std::string &s, int lo, int hi, const char *what) {
  std::string t = s;
  if (t.empty()) ERR2("spec", what << ": empty value")
  size_t i = 0;
  bool neg = false;
  if (t[0] == '-' || t[0] == '+') { neg = t[0] == '-'; i = 1; }
  if (i >= t.size() || t.size() - i > 9) ERR2("spec", what << ": '" << s << "' is not an integer")
  long v = 0;
  for (; i < t.size(); i++) {
    if (t[i] < '0' || t[i] > '9') ERR2("spec", what << ": '" << s << "' is not an integer")
    v = v * 10 + (t[i] - '0');
  }
  if (neg) v = -v;
  if (v < lo || v > hi)
    ERR2("spec", what << ": " << s << " is out of range (" << lo << ".." << hi << ")")
  return (int)v;
}

unsigned SpecPure::parsePort(const std::string &s, const char *what) {
  return (unsigned)SpecPure::parseIntInRange(s, 1, 65535, what);
}
