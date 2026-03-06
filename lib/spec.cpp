// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "spec.h"
#include "config.h"
#include "util.h"
#include "err.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml-cpp/yaml.h>
#include <rang.hpp>

#include <string>
#include <set>
#include <map>
#include <list>
#include <iostream>
#include <sstream>
#include <fstream>

#include "lst-all-script-sections.h" // generated from create.cpp and run.cpp by the Makefile

#define ERR(msg...) \
  ERR2("spec parser", msg)

// all options
static std::list<std::string> allOptionsLst = {"x11", "net", "ssl-certs", "tor", "video", "gl", "no-rm-static-libs", "dbg-ktrace"}; // the order is important for option processing
static std::set<std::string> allOptionsSet(std::begin(allOptionsLst), std::end(allOptionsLst));

// helpers
static std::string AsString(const YAML::Node &node) {
  return node.template as<std::string>();
}

// some generic programming magic
static void Add(std::vector<std::string> &container, const std::string &val) {
  container.push_back(val);
}
static void Add(std::set<std::string> &container, const std::string &val) {
  container.insert(val);
}
static void Add(std::map<std::string, std::shared_ptr<Spec::OptDetails>> &container, const std::string &val) {
  (void)container[val];
}
static void Add(std::vector<std::pair<Spec::NetOptDetails::PortRange, Spec::NetOptDetails::PortRange>> &container, const std::string &val) {
  auto vali = Util::toUInt(val);
  container.push_back({{vali, vali}, {vali, vali}});
}

static std::map<std::string, std::string> parseScriptsSection(const std::string &section, const YAML::Node &node) {
  auto isSequenceOfScalars = [](const YAML::Node &node) {
    if (!node.IsSequence() || node.size() == 0)
      return false;
    for (auto &s : node)
      if (!s.IsScalar())
        return false;

    return true;
  };
  auto isSequenceOfSequenceOfScalars = [isSequenceOfScalars](const YAML::Node &node) {
    if (!node.IsSequence() || node.size() == 0)
      return false;
    for (auto &n : node) {
      if (!isSequenceOfScalars(n))
        return false;
      for (auto &ns : n)
        if (!ns.IsScalar())
          return false;
    }

    return true;
  };
  auto listOrScalar = [&section,isSequenceOfScalars](const YAML::Node &node, std::string &out) { // expect a scalar or the array of scalars
    if (node.IsScalar()) {
      out = STR(AsString(node) << std::endl);
      return true;
    } else if (isSequenceOfScalars(node)) {
      std::ostringstream ss;
      for (auto line : node) {
        if (!line.IsScalar())
          ERR("scalar expected as a script line in '" << section << "': line.Type=" << line.Type())
        ss << AsString(line) << std::endl;
      }
      out = ss.str();
      return true;
    } else {
      return false;
    }
  };

  // Supported layouts:
  // * Scalar
  // * array of scalars => 1 multi-line
  // * array of array of scalar
  // * map of {scalar, array of scalar}

  static const char *errMsg = "scripts must be scalars, arrays of scalars, arrays of arrays of scalars, or maps of scalars or of arrays of scalars";

  std::string str;
  if (listOrScalar(node, str)) { // a single single-line script OR a single multi-line script
    return {{"", str}};
  } else if (isSequenceOfSequenceOfScalars(node)) { // array of array of scalar
    std::map<std::string, std::string> m;
    unsigned idx = 1;
    for (auto elt : node)
      if (listOrScalar(elt, str))
        m[STR("script#" << idx++)] = str;
      else
        ERR(errMsg << " '" << section << "' #1")
    return m;
  } else if (node.IsMap()) { // map of {scalar, array of scalar}
    std::map<std::string, std::string> m;
    for (auto namedScript : node)
      if (listOrScalar(namedScript.second, str))
        m[AsString(namedScript.first)] = str;
      else
        ERR(errMsg << ", problematic section '" << section << "' #2")
    return m;
  } else {
    ERR(errMsg << " '" << section << "' #3")
  }
}

static Spec::NetOptDetails::PortRange parsePortRange(const std::string &str) {
  auto hyphen = str.find('-');
  return hyphen == std::string::npos ?
    Spec::NetOptDetails::PortRange(Util::toUInt(str), Util::toUInt(str))
    :
    Spec::NetOptDetails::PortRange(Util::toUInt(str.substr(0, hyphen)), Util::toUInt(str.substr(hyphen + 1)));
}

//
// methods
//

Spec::OptDetails::~OptDetails() {
}

Spec::NetOptDetails::NetOptDetails()
: outboundWan(false),
  outboundLan(false),
  outboundHost(false),
  outboundDns(false),
  ipv6(false)
{ }

std::shared_ptr<Spec::NetOptDetails> Spec::NetOptDetails::createDefault() {
  // default "net" options allow all outbound and no inbound
  auto d = std::make_shared<NetOptDetails>();
  d->outboundWan  = true; // all outbound is allowed by default
  d->outboundLan  = true;
  d->outboundHost = true;
  d->outboundDns  = true;
  return d;
}

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

const Spec::NetOptDetails* Spec::optionNet() const {
  return getOptionDetails<Spec::NetOptDetails>("net");
}


Spec::NetOptDetails* Spec::optionNetWr() const {
  return getOptionDetailsWr<Spec::NetOptDetails>("net");
}
const Spec::TorOptDetails* Spec::optionTor() const {
  return getOptionDetails<Spec::TorOptDetails>("tor");
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

Spec::TorOptDetails::TorOptDetails()
: controlPort(false)
{ }

std::shared_ptr<Spec::TorOptDetails> Spec::TorOptDetails::createDefault() {
  // default "tor" option runs tor in the default mode, which is to just have the http proxy port open, and nothing else
  return std::make_shared<TorOptDetails>();
}

// preprocess function processes some options, etc. for simplicity of use both by users and by our 'create' module
Spec Spec::preprocess() const {
  Spec spec = *this;

  // helpers
  auto O = [&spec](auto o, bool keep) {
    if (spec.optionExists(o)) {
      if (!keep)
        spec.options.erase(o);
      return true;
    }
    return false;
  };

  // ssl-certs option => install the ca_root_nss package
  if (O("ssl-certs", false))
    spec.pkgInstall.push_back("ca_root_nss");

  // tor option => several actions need to be taken
  if (auto optionTor = spec.optionTor()) {
    // install the tor package
    spec.pkgInstall.push_back("tor");
    // run the service before everything else
    spec.runServices.insert(spec.runServices.begin(), "tor");
    // keep some files that are needed by the tor service to run
    spec.baseKeep.push_back("/usr/bin/limits");
    spec.baseKeep.push_back("/usr/bin/su");
    spec.baseKeep.push_back("/bin/ps");                      // for tor service to validate /var/run/tor/tor.pid file
    spec.baseKeep.push_back("/bin/csh");                     // tor's rc.d script uses csh-style syntax via su -m
    spec.baseKeepWildcard.push_back("/usr/lib/pam_*.so");    // pam is needed for su called by tor
    spec.baseKeepWildcard.push_back("/usr/lib/pam_*.so.*");  // pam is needed for su called by tor
    // optional tor control port
    if (optionTor->controlPort)
      spec.scripts["run:before-start-services"]["openTorControlPort"] = "echo ControlPort 9051 >> /usr/local/etc/tor/torrc";
  }

  // gl option (§22): install GPU drivers based on detected vendor via pciconf
  // Falls back to mesa-dri only (software rendering) if no GPU is detected.
  if (O("gl", false)) {
    spec.pkgInstall.push_back("mesa-dri");
    // Detect GPU vendor from PCI device class 0x030000 (VGA compatible controller)
    try {
      auto pciOutput = Util::execCommandGetOutput(
        {"pciconf", "-l"}, "detect GPU vendor via pciconf");
      if (pciOutput.find("vendor=0x10de") != std::string::npos)
        spec.pkgInstall.push_back("nvidia-driver");          // NVIDIA
      else if (pciOutput.find("vendor=0x1002") != std::string::npos)
        spec.pkgInstall.push_back("drm-kmod");               // AMD/ATI
      else if (pciOutput.find("vendor=0x8086") != std::string::npos)
        spec.pkgInstall.push_back("drm-kmod");               // Intel
      // else: software rendering only (mesa-dri without hw driver)
    } catch (...) {
      // pciconf not available (e.g. in jail) — install nvidia-driver as legacy default
      spec.pkgInstall.push_back("nvidia-driver");
    }
  }

  // dbg-ktrace option => keep the ktrace executable
  if (O("dbg-ktrace", true))
    spec.baseKeep.push_back("/usr/bin/ktrace");

  // Apply system config defaults to networking options
  if (auto optNet = spec.optionNetWr()) {
    auto &cfg = Config::get();

    // Resolve named network for primary interface
    if (!optNet->networkName.empty()) {
      auto it = cfg.networks.find(optNet->networkName);
      if (it != cfg.networks.end()) {
        auto &def = it->second;
        // Apply named network fields only where spec doesn't override
        if (optNet->mode == NetOptDetails::Mode::Nat && !def.mode.empty()) {
          // Mode still at default (Nat) — apply from named network
          if (def.mode == "bridge")            optNet->mode = NetOptDetails::Mode::Bridge;
          else if (def.mode == "passthrough")  optNet->mode = NetOptDetails::Mode::Passthrough;
          else if (def.mode == "netgraph")     optNet->mode = NetOptDetails::Mode::Netgraph;
        }
        if (optNet->bridgeIface.empty() && !def.bridge.empty())
          optNet->bridgeIface = def.bridge;
        if (optNet->passthroughIface.empty() && !def.interface.empty())
          optNet->passthroughIface = def.interface;
        if (optNet->netgraphIface.empty() && !def.interface.empty())
          optNet->netgraphIface = def.interface;
        if (optNet->gateway.empty() && !def.gateway.empty())
          optNet->gateway = def.gateway;
        if (optNet->vlanId < 0 && def.vlan >= 0)
          optNet->vlanId = def.vlan;
        if (!optNet->staticMac && def.staticMac)
          optNet->staticMac = true;
        if (optNet->ip6Mode == NetOptDetails::Ip6Mode::None && !def.ip6.empty()) {
          if (def.ip6 == "slaac")
            optNet->ip6Mode = NetOptDetails::Ip6Mode::Slaac;
          else if (def.ip6 != "none") {
            optNet->ip6Mode = NetOptDetails::Ip6Mode::Static;
            optNet->staticIp6 = def.ip6;
          }
        }
      }
    }

    // Resolve named networks for extra interfaces
    for (auto &ex : optNet->extraInterfaces) {
      if (ex.networkName.empty())
        continue;
      auto it = cfg.networks.find(ex.networkName);
      if (it == cfg.networks.end())
        continue;
      auto &def = it->second;
      if (!def.mode.empty()) {
        if (def.mode == "bridge" && ex.bridgeIface.empty())
          ex.mode = NetOptDetails::Mode::Bridge;
        else if (def.mode == "passthrough" && ex.passthroughIface.empty())
          ex.mode = NetOptDetails::Mode::Passthrough;
        else if (def.mode == "netgraph" && ex.netgraphIface.empty())
          ex.mode = NetOptDetails::Mode::Netgraph;
      }
      if (ex.bridgeIface.empty() && !def.bridge.empty())
        ex.bridgeIface = def.bridge;
      if (ex.passthroughIface.empty() && !def.interface.empty())
        ex.passthroughIface = def.interface;
      if (ex.netgraphIface.empty() && !def.interface.empty())
        ex.netgraphIface = def.interface;
      if (ex.gateway.empty() && !def.gateway.empty())
        ex.gateway = def.gateway;
      if (ex.vlanId < 0 && def.vlan >= 0)
        ex.vlanId = def.vlan;
      if (!ex.staticMac && def.staticMac)
        ex.staticMac = true;
      if (ex.ip6Mode == NetOptDetails::Ip6Mode::None && !def.ip6.empty()) {
        if (def.ip6 == "slaac")
          ex.ip6Mode = NetOptDetails::Ip6Mode::Slaac;
        else if (def.ip6 != "none") {
          ex.ip6Mode = NetOptDetails::Ip6Mode::Static;
          ex.staticIp6 = def.ip6;
        }
      }
    }

    // Use default bridge from config if bridge mode but no bridge specified
    if (optNet->mode == NetOptDetails::Mode::Bridge && optNet->bridgeIface.empty() && !cfg.defaultBridge.empty())
      optNet->bridgeIface = cfg.defaultBridge;
    // Apply system-wide static MAC default if not explicitly configured in spec
    if (optNet->mode != NetOptDetails::Mode::Nat && !optNet->staticMac && cfg.staticMacDefault)
      optNet->staticMac = true;
  }

  return spec;
}

void Spec::validate() const {
  // helpers
  auto isFullPath = [](const std::string &path) {
    return path[0] == '/';
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

  // shared directories must be full paths
  for (auto &dirShare : dirsShare)
    if (!isFullPath(Util::pathSubstituteVarsInPath(dirShare.first)) || !isFullPath(Util::pathSubstituteVarsInPath(dirShare.second)))
      ERR("the shared directory paths have to be a full paths, share=" << dirShare.first << "->" << dirShare.second)

  // shared files must be full paths
  for (auto &fileShare : filesShare)
    if (!isFullPath(Util::pathSubstituteVarsInPath(fileShare.first)) || !isFullPath(Util::pathSubstituteVarsInPath(fileShare.second)))
      ERR("the shared directory paths have to be a full paths, share=" << fileShare.first << "->" << fileShare.second)

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
    // outbound/inbound controls only apply to NAT mode
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
    // IPv6 SLAAC/static only valid for non-NAT modes (NAT uses ipv6: true/false for ULA pass-through)
    if (optNet->ip6Mode != Spec::NetOptDetails::Ip6Mode::None && optNet->mode == Mode::Nat)
      ERR("options/net/ip6 (slaac/static) is only valid with bridge, passthrough, or netgraph mode; use ipv6: true for NAT mode")
    if (optNet->ip6Mode == Spec::NetOptDetails::Ip6Mode::Static && optNet->staticIp6.empty())
      ERR("options/net/ip6 with static address requires an IPv6 address (e.g. fd00::50/64)")
    // Extra interfaces can only be used with non-NAT primary mode
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

  // COW validation (§6)
  if (cowOptions) {
    if (cowOptions->mode != "ephemeral" && cowOptions->mode != "persistent")
      ERR("cow/mode must be 'ephemeral' or 'persistent'")
    if (cowOptions->backend != "zfs" && cowOptions->backend != "unionfs")
      ERR("cow/backend must be 'zfs' or 'unionfs'")
  }

  // clipboard validation (§12)
  if (clipboardOptions) {
    if (clipboardOptions->mode != "isolated" && clipboardOptions->mode != "shared" && clipboardOptions->mode != "none")
      ERR("clipboard/mode must be 'isolated', 'shared', or 'none'")
  }

  // D-Bus validation (§13)
  if (dbusOptions) {
    if (!dbusOptions->systemBus && !dbusOptions->sessionBus)
      ERR("dbus section present but both system and session are disabled")
  }

  // managed services validation (§14)
  for (auto &ms : managedServices)
    if (ms.name.empty())
      ERR("managed service entry missing name")

  // socket proxy validation (§15)
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

  // firewall policy validation (§3)
  if (firewallPolicy) {
    for (auto port : firewallPolicy->allowTcp)
      if (port == 0 || port > 65535)
        ERR("firewall/allow-tcp port out of range: " << port)
    for (auto port : firewallPolicy->allowUdp)
      if (port == 0 || port > 65535)
        ERR("firewall/allow-udp port out of range: " << port)
  }

  // terminal validation (§16)
  if (terminalOptions) {
    if (terminalOptions->devfsRuleset != -1 && (terminalOptions->devfsRuleset < 0 || terminalOptions->devfsRuleset > 65535))
      ERR("terminal/devfs_ruleset must be 0-65535")
  }
}

//
// interface
//

static std::string substituteVars(const std::string &input, const std::map<std::string, std::string> &vars) {
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

static Spec parseSpecFromNode(YAML::Node top) {

  Spec spec;

  // helper functions
  auto isKey = [](auto &k, const char *s) {
    return AsString(k.first) == s;
  };
  auto scalar = [](auto &node, std::string &out, const char *opath) {
    if (node.IsScalar()) {
      out = AsString(node);
    } else {
      ERR("unsupported " << opath << " object of type " << node.Type() << ", only scalar is allowed")
    }
  };
  auto listOrScalar = [](auto &node, auto &out, const char *opath) {
    if (node.IsSequence()) {
      for (auto r : node)
        Add(out, AsString(r));
      return true;
    } else if (node.IsScalar()) {
      for (auto &e : Util::splitString(AsString(node), " "))
        Add(out, e);
      return true;
    } else {
      return false;
    }
  };
  auto listOrScalarOnly = [listOrScalar](auto &node, auto &out, const char *opath) {
    if (!listOrScalar(node, out, opath))
      ERR("unsupported " << opath << " object of type " << node.Type() << ", only list or scalar are allowed")
  };

  // top-level tags
  for (auto k : top) {
    if (isKey(k, "base")) {
      for (auto b : k.second) {
        if (isKey(b, "keep")) {
          listOrScalarOnly(b.second, spec.baseKeep, "base/keep");
        } else if (isKey(b, "keep-wildcard")) {
          listOrScalarOnly(b.second, spec.baseKeepWildcard, "base/keep-wildcard");
        } else if (isKey(b, "remove")) {
          listOrScalarOnly(b.second, spec.baseRemove, "base/remove");
        } else {
          ERR("unknown element base/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "pkg")) {
      for (auto b : k.second) {
        if (isKey(b, "install")) {
          listOrScalarOnly(b.second, spec.pkgInstall, "pkg/install");
        } else if (isKey(b, "local-override")) {
          if (!b.second.IsMap())
            ERR("pkg/local-override must be a map of package name to local package file path")
          for (auto lo : b.second)
            spec.pkgLocalOverride.push_back({AsString(lo.first), AsString(lo.second)});
        } else if (isKey(b, "add")) {
          ERR("pkg/add is not yet implemented — use pkg/install instead")
        } else if (isKey(b, "nuke")) {
          listOrScalarOnly(b.second, spec.pkgNuke, "pkg/nuke");
        } else {
          ERR("unknown element pkg/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "run")) {
      for (auto b : k.second) {
        if (isKey(b, "command")) {
          std::string command;
          scalar(b.second, command, "run/command");
          auto space = command.find(' ');
          if (space == std::string::npos)
            spec.runCmdExecutable = command;
          else {
            spec.runCmdExecutable = command.substr(0, space);
            spec.runCmdArgs = command.substr(space);
          }
        } else if (isKey(b, "service")) {
          listOrScalarOnly(b.second, spec.runServices, "run/service");
        } else {
          ERR("unknown element run/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "dirs")) {
      for (auto b : k.second) {
        if (isKey(b, "share")) {
          if (b.second.IsSequence()) {
            for (auto oneShare : b.second) {
              if (oneShare.IsScalar())
                spec.dirsShare.push_back({AsString(oneShare), AsString(oneShare)});
              else if (oneShare.IsSequence() && oneShare.size() == 2) {
                spec.dirsShare.push_back({AsString(oneShare[0]), AsString(oneShare[1])});
              } else {
                ERR("elements of the dirs/share list have to be scalars or lists of size two (fromDir, toDir)")
              }
            }
          } else {
            ERR("dirs/share has to be a list")
          }
        } else {
          ERR("unknown element dirs/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "files")) {
      for (auto b : k.second) {
        if (isKey(b, "share")) {
          if (b.second.IsSequence()) {
            for (auto oneShare : b.second) {
              if (oneShare.IsScalar())
                spec.filesShare.push_back({AsString(oneShare), AsString(oneShare)});
              else if (oneShare.IsSequence() && oneShare.size() == 2) {
                spec.filesShare.push_back({AsString(oneShare[0]), AsString(oneShare[1])});
              } else {
                ERR("elements of the files/share list have to be scalars or lists of size two (fromFile, toFile)")
              }
            }
          }
        }
      }
    } else if (isKey(k, "options")) {
      if (listOrScalar(k.second, spec.options, "options")) {
        // options are a list (simplified format): set details to options that support them
        auto itNet = spec.options.find("net");
        if (itNet != spec.options.end())
          itNet->second = Spec::NetOptDetails::createDefault(); // default "net" option details
        auto itTor = spec.options.find("tor");
        if (itTor != spec.options.end()) {
          itTor->second = Spec::TorOptDetails::createDefault(); // default "tor" option details
          spec.options["net"] = std::make_shared<Spec::NetOptDetails>(); // blank "net" option details
          spec.optionNetWr()->outboundWan = true; // only WAN, DNS isn't needed for Tor
        }
      } else if (k.second.IsMap()) {
        // options are a map: they are in the extended format, parse them in a custom fashion, one by one
        std::set<std::string> opts;
        for (auto lo : k.second) {
          auto soptName = AsString(lo.first);
          if (!lo.second.IsMap() && !lo.second.IsNull())
            ERR("options/" << soptName << " value must be a map or empty when options are in the extended format")
          opts.insert(soptName);
        }
        for (auto &soptName : allOptionsLst)
          if (opts.find(soptName) != opts.end()) {
            const auto &soptVal = k.second[soptName];
            auto &optVal = spec.options[soptName];
            if (soptName == "net") {
              if (soptVal.IsMap()) {
                optVal = std::make_shared<Spec::NetOptDetails>(); // blank "net" option details
                auto optNetDetails = static_cast<Spec::NetOptDetails*>(optVal.get());
                for (auto netOpt : soptVal) {
                  if (AsString(netOpt.first) == "outbound") {
                    std::set<std::string> outboundSet;
                    listOrScalarOnly(netOpt.second, outboundSet, "net/outbound");
                    for (auto &v : outboundSet)
                      if (v == "all") {
                        if (outboundSet.size() > 1)
                          ERR("net/outbound contains other elements besides 'all'")
                        optNetDetails->outboundWan = true;
                        optNetDetails->outboundLan = true;
                        optNetDetails->outboundHost = true;
                        optNetDetails->outboundDns = true;
                      } else if (v == "none") {
                        if (outboundSet.size() > 1)
                          ERR("net/outbound contains other elements besides 'none'")
                      } else if (v == "wan") {
                        optNetDetails->outboundWan = true;
                      } else if (v == "lan") {
                        optNetDetails->outboundLan = true;
                      } else if (v == "host") {
                        optNetDetails->outboundHost = true;
                      } else if (v == "dns") {
                        optNetDetails->outboundDns = true;
                      } else {
                        ERR("net/outbound contains the unknown element '" << v << "'")
                      }
                  } else if (AsString(netOpt.first) == "inbound-tcp") {
                    if (listOrScalar(netOpt.second, optNetDetails->inboundPortsTcp, "options")) {
                    } else if (netOpt.second.IsMap()) {
                      for (auto portsPair : netOpt.second)
                        optNetDetails->inboundPortsTcp.push_back({parsePortRange(portsPair.first.as<std::string>()), parsePortRange(portsPair.second.as<std::string>())});
                    } else {
                      ERR("options/net/inbound-tcp value must be an array, a scalar or a map")
                    }
                  } else if (AsString(netOpt.first) == "inbound-udp") {
                    if (listOrScalar(netOpt.second, optNetDetails->inboundPortsUdp, "options")) {
                    } else if (netOpt.second.IsMap()) {
                      for (auto portsPair : netOpt.second)
                        optNetDetails->inboundPortsUdp.push_back({parsePortRange(portsPair.first.as<std::string>()), parsePortRange(portsPair.second.as<std::string>())});
                    } else {
                      ERR("options/net/inbound-udp value must be an array, a scalar or a map")
                    }
                  } else if (AsString(netOpt.first) == "ipv6") {
                    if (netOpt.second.IsScalar()) {
                      auto v6str = AsString(netOpt.second);
                      if (v6str == "true" || v6str == "yes")
                        optNetDetails->ipv6 = true;
                      else if (v6str == "false" || v6str == "no")
                        optNetDetails->ipv6 = false;
                      else if (v6str == "slaac") {
                        optNetDetails->ip6Mode = Spec::NetOptDetails::Ip6Mode::Slaac;
                      } else if (v6str == "none") {
                        optNetDetails->ip6Mode = Spec::NetOptDetails::Ip6Mode::None;
                      } else {
                        // treat as static IPv6 address
                        optNetDetails->ip6Mode = Spec::NetOptDetails::Ip6Mode::Static;
                        optNetDetails->staticIp6 = v6str;
                      }
                    } else if (!YAML::convert<bool>::decode(netOpt.second, optNetDetails->ipv6))
                      ERR("options/net/ipv6 value must be a boolean, 'slaac', 'none', or an IPv6 address")
                  } else if (AsString(netOpt.first) == "network") {
                    optNetDetails->networkName = AsString(netOpt.second);
                  } else if (AsString(netOpt.first) == "mode") {
                    auto modeStr = AsString(netOpt.second);
                    if (modeStr == "nat")
                      optNetDetails->mode = Spec::NetOptDetails::Mode::Nat;
                    else if (modeStr == "bridge")
                      optNetDetails->mode = Spec::NetOptDetails::Mode::Bridge;
                    else if (modeStr == "passthrough")
                      optNetDetails->mode = Spec::NetOptDetails::Mode::Passthrough;
                    else if (modeStr == "netgraph")
                      optNetDetails->mode = Spec::NetOptDetails::Mode::Netgraph;
                    else
                      ERR("options/net/mode must be 'nat', 'bridge', 'passthrough', or 'netgraph'")
                  } else if (AsString(netOpt.first) == "bridge") {
                    optNetDetails->bridgeIface = AsString(netOpt.second);
                  } else if (AsString(netOpt.first) == "interface") {
                    // used for passthrough and netgraph modes
                    optNetDetails->passthroughIface = AsString(netOpt.second);
                    optNetDetails->netgraphIface = AsString(netOpt.second);
                  } else if (AsString(netOpt.first) == "ip") {
                    auto ipStr = AsString(netOpt.second);
                    if (ipStr == "dhcp")
                      optNetDetails->ipMode = Spec::NetOptDetails::IpMode::Dhcp;
                    else if (ipStr == "none")
                      optNetDetails->ipMode = Spec::NetOptDetails::IpMode::None;
                    else {
                      optNetDetails->ipMode = Spec::NetOptDetails::IpMode::Static;
                      optNetDetails->staticIp = ipStr;
                    }
                  } else if (AsString(netOpt.first) == "gateway") {
                    optNetDetails->gateway = AsString(netOpt.second);
                  } else if (AsString(netOpt.first) == "ip6") {
                    auto v6str = AsString(netOpt.second);
                    if (v6str == "slaac")
                      optNetDetails->ip6Mode = Spec::NetOptDetails::Ip6Mode::Slaac;
                    else if (v6str == "none")
                      optNetDetails->ip6Mode = Spec::NetOptDetails::Ip6Mode::None;
                    else {
                      optNetDetails->ip6Mode = Spec::NetOptDetails::Ip6Mode::Static;
                      optNetDetails->staticIp6 = v6str;
                    }
                  } else if (AsString(netOpt.first) == "static-mac") {
                    if (!YAML::convert<bool>::decode(netOpt.second, optNetDetails->staticMac))
                      ERR("options/net/static-mac must be a boolean")
                  } else if (AsString(netOpt.first) == "vlan") {
                    optNetDetails->vlanId = netOpt.second.as<int>();
                    if (optNetDetails->vlanId < 1 || optNetDetails->vlanId > 4094)
                      ERR("options/net/vlan must be 1-4094")
                  } else if (AsString(netOpt.first) == "extra") {
                    if (!netOpt.second.IsSequence())
                      ERR("options/net/extra must be a list of interface configurations")
                    for (auto extraNode : netOpt.second) {
                      if (!extraNode.IsMap())
                        ERR("each entry in options/net/extra must be a map")
                      Spec::NetOptDetails::ExtraInterface extra;
                      for (auto e : extraNode) {
                        auto eKey = AsString(e.first);
                        if (eKey == "network") {
                          extra.networkName = AsString(e.second);
                        } else if (eKey == "mode") {
                          auto m = AsString(e.second);
                          if (m == "bridge") extra.mode = Spec::NetOptDetails::Mode::Bridge;
                          else if (m == "passthrough") extra.mode = Spec::NetOptDetails::Mode::Passthrough;
                          else if (m == "netgraph") extra.mode = Spec::NetOptDetails::Mode::Netgraph;
                          else ERR("options/net/extra[]/mode must be 'bridge', 'passthrough', or 'netgraph'")
                        } else if (eKey == "bridge") {
                          extra.bridgeIface = AsString(e.second);
                        } else if (eKey == "interface") {
                          extra.passthroughIface = AsString(e.second);
                          extra.netgraphIface = AsString(e.second);
                        } else if (eKey == "ip") {
                          auto ipStr = AsString(e.second);
                          if (ipStr == "dhcp") extra.ipMode = Spec::NetOptDetails::IpMode::Dhcp;
                          else if (ipStr == "none") extra.ipMode = Spec::NetOptDetails::IpMode::None;
                          else { extra.ipMode = Spec::NetOptDetails::IpMode::Static; extra.staticIp = ipStr; }
                        } else if (eKey == "gateway") {
                          extra.gateway = AsString(e.second);
                        } else if (eKey == "ip6") {
                          auto v6 = AsString(e.second);
                          if (v6 == "slaac") extra.ip6Mode = Spec::NetOptDetails::Ip6Mode::Slaac;
                          else if (v6 == "none") extra.ip6Mode = Spec::NetOptDetails::Ip6Mode::None;
                          else { extra.ip6Mode = Spec::NetOptDetails::Ip6Mode::Static; extra.staticIp6 = v6; }
                        } else if (eKey == "static-mac") {
                          if (!YAML::convert<bool>::decode(e.second, extra.staticMac))
                            ERR("options/net/extra[]/static-mac must be a boolean")
                        } else if (eKey == "vlan") {
                          extra.vlanId = e.second.as<int>();
                          if (extra.vlanId < 1 || extra.vlanId > 4094)
                            ERR("options/net/extra[]/vlan must be 1-4094")
                        } else {
                          ERR("unknown field options/net/extra[]/" << eKey)
                        }
                      }
                      optNetDetails->extraInterfaces.push_back(std::move(extra));
                    }
                  } else
                    ERR("the invalid value options/net/" << netOpt.first << " supplied")
                }
              } else
                optVal = Spec::NetOptDetails::createDefault(); // default "net" option details
            } else if (soptName == "tor") { // ASSUME that the "tor" option is after the "net" option
              optVal = std::make_shared<Spec::TorOptDetails>(); // blank "tor" option details
              if (soptVal.IsMap()) {
                auto optTorDetails = static_cast<Spec::TorOptDetails*>(optVal.get());
                for (auto torOpt : soptVal) {
                  if (AsString(torOpt.first) == "control-port") {
                    if (!YAML::convert<bool>::decode(torOpt.second, optTorDetails->controlPort))
                      ERR("options/tor/control-port can't be converted to boolean: " << torOpt.second.as<std::string>())
                  } else
                    ERR("the invalid value options/tor/" << torOpt.first << " supplied")
                }
              }
              // always set options/net/wan for tor
              if (!spec.optionExists("net"))
                spec.options["net"] = std::make_shared<Spec::NetOptDetails>(); // blank "net" option details
              spec.optionNetWr()->outboundWan = true; // only WAN, DNS isn't needed for Tor
            } else {
              if (!soptVal.IsNull())
                ERR("options/* values must be empty when options are in the extended format")
            }
        }
      } else {
        ERR("options are not scalar, list or map")
      }
    } else if (isKey(k, "zfs")) {
      for (auto b : k.second) {
        if (isKey(b, "datasets")) {
          listOrScalarOnly(b.second, spec.zfsDatasets, "zfs/datasets");
        } else {
          ERR("unknown element zfs/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "ipc")) {
      if (!k.second.IsMap())
        ERR("ipc must be a map")
      for (auto b : k.second) {
        if (isKey(b, "sysvipc")) {
          if (!YAML::convert<bool>::decode(b.second, spec.allowSysvipc))
            ERR("ipc/sysvipc must be a boolean")
        } else if (isKey(b, "raw_sockets") || isKey(b, "raw-sockets")) {
          spec.ipcRawSocketsOverride = true;
          if (!YAML::convert<bool>::decode(b.second, spec.ipcRawSocketsValue))
            ERR("ipc/raw_sockets must be a boolean")
        } else if (isKey(b, "mqueue")) {
          if (!YAML::convert<bool>::decode(b.second, spec.allowMqueue))
            ERR("ipc/mqueue must be a boolean")
        } else {
          ERR("unknown element ipc/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "limits")) {
      if (!k.second.IsMap())
        ERR("limits must be a map of resource-name to value")
      for (auto b : k.second)
        spec.limits[AsString(b.first)] = AsString(b.second);
    } else if (isKey(k, "encrypted")) {
      if (k.second.IsScalar()) {
        // simple form: encrypted: true
        if (!YAML::convert<bool>::decode(k.second, spec.encrypted))
          ERR("encrypted must be a boolean or a map")
      } else if (k.second.IsMap()) {
        spec.encrypted = true;
        for (auto b : k.second) {
          if (isKey(b, "method"))
            scalar(b.second, spec.encryptionMethod, "encrypted/method");
          else if (isKey(b, "keyformat"))
            scalar(b.second, spec.encryptionKeyformat, "encrypted/keyformat");
          else if (isKey(b, "cipher"))
            scalar(b.second, spec.encryptionCipher, "encrypted/cipher");
          else
            ERR("unknown element encrypted/" << b.first << " in spec")
        }
      } else {
        ERR("encrypted must be a boolean or a map")
      }
    } else if (isKey(k, "dns_filter") || isKey(k, "dns-filter")) {
      if (!k.second.IsMap())
        ERR("dns_filter must be a map")
      spec.dnsFilter = std::make_unique<Spec::DnsFilter>();
      for (auto b : k.second) {
        if (isKey(b, "allow")) {
          listOrScalarOnly(b.second, spec.dnsFilter->allow, "dns_filter/allow");
        } else if (isKey(b, "block")) {
          listOrScalarOnly(b.second, spec.dnsFilter->block, "dns_filter/block");
        } else if (isKey(b, "redirect_blocked") || isKey(b, "redirect-blocked")) {
          scalar(b.second, spec.dnsFilter->redirectBlocked, "dns_filter/redirect_blocked");
        } else {
          ERR("unknown element dns_filter/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "security")) {
      if (!k.second.IsMap())
        ERR("security must be a map")
      for (auto b : k.second) {
        if (isKey(b, "enforce_statfs") || isKey(b, "enforce-statfs")) {
          spec.enforceStatfs = Util::toUInt(AsString(b.second));
        } else if (isKey(b, "allow_quotas") || isKey(b, "allow-quotas")) {
          if (!YAML::convert<bool>::decode(b.second, spec.allowQuotas))
            ERR("security/allow_quotas must be a boolean")
        } else if (isKey(b, "allow_set_hostname") || isKey(b, "allow-set-hostname")) {
          if (!YAML::convert<bool>::decode(b.second, spec.allowSetHostname))
            ERR("security/allow_set_hostname must be a boolean")
        } else if (isKey(b, "allow_chflags") || isKey(b, "allow-chflags")) {
          if (!YAML::convert<bool>::decode(b.second, spec.allowChflags))
            ERR("security/allow_chflags must be a boolean")
        } else if (isKey(b, "allow_mlock") || isKey(b, "allow-mlock")) {
          if (!YAML::convert<bool>::decode(b.second, spec.allowMlock))
            ERR("security/allow_mlock must be a boolean")
        } else if (isKey(b, "securelevel") || isKey(b, "secure-level")) {
          spec.securelevel = Util::toUInt(AsString(b.second));
          if (spec.securelevel < -1 || spec.securelevel > 3)
            ERR("security/securelevel must be between -1 and 3")
        } else if (isKey(b, "children_max") || isKey(b, "children-max")) {
          spec.childrenMax = std::stoi(AsString(b.second));
          if (spec.childrenMax < 0)
            ERR("security/children_max must be >= 0")
        } else if (isKey(b, "cpuset") || isKey(b, "cpu-set")) {
          spec.cpuset = AsString(b.second);
        } else {
          ERR("unknown element security/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "cow")) {
      // Copy-on-Write filesystem (§6)
      if (!k.second.IsMap())
        ERR("cow must be a map")
      spec.cowOptions = std::make_unique<Spec::CowOptions>();
      spec.cowOptions->backend = "zfs";
      spec.cowOptions->mode = "ephemeral";
      for (auto b : k.second) {
        if (isKey(b, "mode")) {
          scalar(b.second, spec.cowOptions->mode, "cow/mode");
          if (spec.cowOptions->mode != "ephemeral" && spec.cowOptions->mode != "persistent")
            ERR("cow/mode must be 'ephemeral' or 'persistent'")
        } else if (isKey(b, "backend")) {
          scalar(b.second, spec.cowOptions->backend, "cow/backend");
          if (spec.cowOptions->backend != "zfs" && spec.cowOptions->backend != "unionfs")
            ERR("cow/backend must be 'zfs' or 'unionfs'")
        } else {
          ERR("unknown element cow/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "x11")) {
      // GUI/Desktop isolation (§11) — top-level x11 section
      if (k.second.IsMap()) {
        spec.x11Options = std::make_unique<Spec::X11Options>();
        for (auto b : k.second) {
          if (isKey(b, "mode")) {
            scalar(b.second, spec.x11Options->mode, "x11/mode");
            if (spec.x11Options->mode != "nested" && spec.x11Options->mode != "shared" && spec.x11Options->mode != "none")
              ERR("x11/mode must be 'nested', 'shared', or 'none'")
          } else if (isKey(b, "resolution")) {
            scalar(b.second, spec.x11Options->resolution, "x11/resolution");
          } else if (isKey(b, "clipboard")) {
            if (!YAML::convert<bool>::decode(b.second, spec.x11Options->clipboardEnabled))
              ERR("x11/clipboard must be a boolean")
          } else {
            ERR("unknown element x11/" << b.first << " in spec")
          }
        }
        // ensure x11 is in options map for optionExists("x11")
        if (spec.options.find("x11") == spec.options.end())
          spec.options["x11"] = nullptr;
      } else if (k.second.IsScalar()) {
        // simple form: x11: true
        bool val;
        if (YAML::convert<bool>::decode(k.second, val) && val)
          spec.options["x11"] = nullptr;
      } else {
        ERR("x11 must be a map or boolean")
      }
    } else if (isKey(k, "clipboard")) {
      // Clipboard isolation (§12)
      if (!k.second.IsMap())
        ERR("clipboard must be a map")
      spec.clipboardOptions = std::make_unique<Spec::ClipboardOptions>();
      for (auto b : k.second) {
        if (isKey(b, "mode")) {
          scalar(b.second, spec.clipboardOptions->mode, "clipboard/mode");
          if (spec.clipboardOptions->mode != "isolated" && spec.clipboardOptions->mode != "shared" && spec.clipboardOptions->mode != "none")
            ERR("clipboard/mode must be 'isolated', 'shared', or 'none'")
        } else if (isKey(b, "direction")) {
          scalar(b.second, spec.clipboardOptions->direction, "clipboard/direction");
          if (spec.clipboardOptions->direction != "in" && spec.clipboardOptions->direction != "out"
              && spec.clipboardOptions->direction != "both" && spec.clipboardOptions->direction != "none")
            ERR("clipboard/direction must be 'in', 'out', 'both', or 'none'")
        } else {
          ERR("unknown element clipboard/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "dbus")) {
      // D-Bus isolation (§13)
      if (!k.second.IsMap())
        ERR("dbus must be a map")
      spec.dbusOptions = std::make_unique<Spec::DbusOptions>();
      for (auto b : k.second) {
        if (isKey(b, "system")) {
          if (!YAML::convert<bool>::decode(b.second, spec.dbusOptions->systemBus))
            ERR("dbus/system must be a boolean")
        } else if (isKey(b, "session")) {
          if (!YAML::convert<bool>::decode(b.second, spec.dbusOptions->sessionBus))
            ERR("dbus/session must be a boolean")
        } else if (isKey(b, "policy")) {
          if (!b.second.IsMap())
            ERR("dbus/policy must be a map")
          for (auto p : b.second) {
            if (isKey(p, "allow_own") || isKey(p, "allow-own")) {
              listOrScalarOnly(p.second, spec.dbusOptions->allowOwn, "dbus/policy/allow_own");
            } else if (isKey(p, "deny_send") || isKey(p, "deny-send")) {
              listOrScalarOnly(p.second, spec.dbusOptions->denySend, "dbus/policy/deny_send");
            } else {
              ERR("unknown element dbus/policy/" << p.first << " in spec")
            }
          }
        } else {
          ERR("unknown element dbus/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "services")) {
      // Managed services (§14)
      if (!k.second.IsMap())
        ERR("services must be a map")
      for (auto b : k.second) {
        if (isKey(b, "managed")) {
          if (!b.second.IsSequence())
            ERR("services/managed must be a list")
          for (auto svc : b.second) {
            Spec::ManagedService ms;
            if (svc.IsScalar()) {
              ms.name = AsString(svc);
            } else if (svc.IsMap()) {
              for (auto f : svc) {
                if (AsString(f.first) == "name")
                  ms.name = AsString(f.second);
                else if (AsString(f.first) == "enable") {
                  if (!YAML::convert<bool>::decode(f.second, ms.enable))
                    ERR("services/managed/enable must be a boolean")
                } else if (AsString(f.first) == "rcvar")
                  ms.rcvar = AsString(f.second);
                else
                  ERR("unknown field in services/managed: " << f.first)
              }
            } else {
              ERR("services/managed entries must be scalars or maps")
            }
            if (ms.name.empty())
              ERR("services/managed entry missing 'name'")
            spec.managedServices.push_back(ms);
          }
        } else if (isKey(b, "auto_start") || isKey(b, "auto-start")) {
          if (!YAML::convert<bool>::decode(b.second, spec.servicesAutoStart))
            ERR("services/auto_start must be a boolean")
        } else {
          ERR("unknown element services/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "socket_proxy") || isKey(k, "socket-proxy")) {
      // Socket proxy (§15)
      if (!k.second.IsMap())
        ERR("socket_proxy must be a map")
      spec.socketProxy = std::make_unique<Spec::SocketProxy>();
      for (auto b : k.second) {
        if (isKey(b, "share")) {
          listOrScalarOnly(b.second, spec.socketProxy->share, "socket_proxy/share");
        } else if (isKey(b, "proxy")) {
          if (!b.second.IsSequence())
            ERR("socket_proxy/proxy must be a list")
          for (auto p : b.second) {
            if (!p.IsMap())
              ERR("socket_proxy/proxy entries must be maps")
            Spec::SocketProxy::ProxyEntry entry;
            for (auto f : p) {
              if (AsString(f.first) == "host")
                entry.host = AsString(f.second);
              else if (AsString(f.first) == "jail")
                entry.jail = AsString(f.second);
              else if (AsString(f.first) == "direction") {
                entry.direction = AsString(f.second);
                if (entry.direction != "bidirectional" && entry.direction != "in" && entry.direction != "out")
                  ERR("socket_proxy/proxy/direction must be 'bidirectional', 'in', or 'out'")
              } else {
                ERR("unknown field in socket_proxy/proxy: " << f.first)
              }
            }
            if (entry.host.empty() || entry.jail.empty())
              ERR("socket_proxy/proxy entries require 'host' and 'jail' fields")
            spec.socketProxy->proxy.push_back(entry);
          }
        } else {
          ERR("unknown element socket_proxy/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "firewall")) {
      // Per-container firewall policy (§3)
      if (!k.second.IsMap())
        ERR("firewall must be a map")
      spec.firewallPolicy = std::make_unique<Spec::FirewallPolicy>();
      for (auto b : k.second) {
        if (isKey(b, "block-ip") || isKey(b, "block_ip")) {
          listOrScalarOnly(b.second, spec.firewallPolicy->blockIp, "firewall/block-ip");
        } else if (isKey(b, "allow-tcp") || isKey(b, "allow_tcp")) {
          if (b.second.IsSequence()) {
            for (auto p : b.second)
              spec.firewallPolicy->allowTcp.push_back(Util::toUInt(AsString(p)));
          } else if (b.second.IsScalar()) {
            spec.firewallPolicy->allowTcp.push_back(Util::toUInt(AsString(b.second)));
          }
        } else if (isKey(b, "allow-udp") || isKey(b, "allow_udp")) {
          if (b.second.IsSequence()) {
            for (auto p : b.second)
              spec.firewallPolicy->allowUdp.push_back(Util::toUInt(AsString(p)));
          } else if (b.second.IsScalar()) {
            spec.firewallPolicy->allowUdp.push_back(Util::toUInt(AsString(b.second)));
          }
        } else if (isKey(b, "default")) {
          scalar(b.second, spec.firewallPolicy->defaultPolicy, "firewall/default");
          if (spec.firewallPolicy->defaultPolicy != "allow" && spec.firewallPolicy->defaultPolicy != "block")
            ERR("firewall/default must be 'allow' or 'block'")
        } else {
          ERR("unknown element firewall/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "security_advanced") || isKey(k, "security-advanced")) {
      // Advanced security: Capsicum + MAC (§8)
      if (!k.second.IsMap())
        ERR("security_advanced must be a map")
      spec.securityAdvanced = std::make_unique<Spec::SecurityAdvanced>();
      for (auto b : k.second) {
        if (isKey(b, "capsicum")) {
          if (!YAML::convert<bool>::decode(b.second, spec.securityAdvanced->capsicum))
            ERR("security_advanced/capsicum must be a boolean")
        } else if (isKey(b, "mac_bsdextended") || isKey(b, "mac-bsdextended")) {
          listOrScalarOnly(b.second, spec.securityAdvanced->macRules, "security_advanced/mac_bsdextended");
        } else if (isKey(b, "mac_portacl") || isKey(b, "mac-portacl")) {
          if (b.second.IsMap()) {
            for (auto p : b.second) {
              if (AsString(p.first) == "allow_ports" || AsString(p.first) == "allow-ports") {
                if (p.second.IsSequence()) {
                  for (auto port : p.second)
                    spec.securityAdvanced->macAllowPorts.push_back(Util::toUInt(AsString(port)));
                }
              } else {
                ERR("unknown element security_advanced/mac_portacl/" << p.first)
              }
            }
          }
        } else if (isKey(b, "hide_other_jails") || isKey(b, "hide-other-jails")) {
          if (!YAML::convert<bool>::decode(b.second, spec.securityAdvanced->hideOtherJails))
            ERR("security_advanced/hide_other_jails must be a boolean")
        } else {
          ERR("unknown element security_advanced/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "terminal")) {
      // Terminal isolation (§16)
      if (!k.second.IsMap())
        ERR("terminal must be a map")
      spec.terminalOptions = std::make_unique<Spec::TerminalOptions>();
      for (auto b : k.second) {
        if (isKey(b, "devfs_ruleset") || isKey(b, "devfs-ruleset")) {
          spec.terminalOptions->devfsRuleset = Util::toUInt(AsString(b.second));
        } else if (isKey(b, "allow_raw_tty") || isKey(b, "allow-raw-tty")) {
          if (!YAML::convert<bool>::decode(b.second, spec.terminalOptions->allowRawTty))
            ERR("terminal/allow_raw_tty must be a boolean")
        } else {
          ERR("unknown element terminal/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "gui")) {
      // GUI session management (§19)
      if (!k.second.IsMap())
        ERR("gui must be a map")
      spec.guiOptions = std::make_unique<Spec::GuiOptions>();
      for (auto b : k.second) {
        if (isKey(b, "mode")) {
          scalar(b.second, spec.guiOptions->mode, "gui/mode");
          if (spec.guiOptions->mode != "nested" && spec.guiOptions->mode != "headless"
              && spec.guiOptions->mode != "gpu" && spec.guiOptions->mode != "auto")
            ERR("gui/mode must be 'nested', 'headless', 'gpu', or 'auto'")
        } else if (isKey(b, "resolution")) {
          scalar(b.second, spec.guiOptions->resolution, "gui/resolution");
        } else if (isKey(b, "vnc")) {
          if (!YAML::convert<bool>::decode(b.second, spec.guiOptions->vnc))
            ERR("gui/vnc must be a boolean")
        } else if (isKey(b, "vnc_port") || isKey(b, "vnc-port")) {
          spec.guiOptions->vncPort = Util::toUInt(AsString(b.second));
        } else if (isKey(b, "novnc")) {
          if (!YAML::convert<bool>::decode(b.second, spec.guiOptions->novnc))
            ERR("gui/novnc must be a boolean")
        } else if (isKey(b, "vnc_password") || isKey(b, "vnc-password")) {
          scalar(b.second, spec.guiOptions->vncPassword, "gui/vnc_password");
        } else if (isKey(b, "gpu_device") || isKey(b, "gpu-device")) {
          scalar(b.second, spec.guiOptions->gpuDevice, "gui/gpu_device");
        } else if (isKey(b, "gpu_driver") || isKey(b, "gpu-driver")) {
          scalar(b.second, spec.guiOptions->gpuDriver, "gui/gpu_driver");
          if (!spec.guiOptions->gpuDriver.empty() &&
              spec.guiOptions->gpuDriver != "nvidia" && spec.guiOptions->gpuDriver != "amdgpu"
              && spec.guiOptions->gpuDriver != "intel" && spec.guiOptions->gpuDriver != "dummy")
            ERR("gui/gpu_driver must be 'nvidia', 'amdgpu', 'intel', or 'dummy'")
        } else {
          ERR("unknown element gui/" << b.first << " in spec")
        }
      }
    } else if (isKey(k, "healthcheck")) {
      spec.healthcheck = std::make_unique<Spec::Healthcheck>();
      if (k.second.IsScalar()) {
        // Short form: just the test command
        spec.healthcheck->test = AsString(k.second);
      } else if (k.second.IsMap()) {
        for (auto b : k.second) {
          if (isKey(b, "test"))
            scalar(b.second, spec.healthcheck->test, "healthcheck/test");
          else if (isKey(b, "interval")) {
            spec.healthcheck->intervalSec = Util::toUInt(AsString(b.second));
          } else if (isKey(b, "timeout")) {
            spec.healthcheck->timeoutSec = Util::toUInt(AsString(b.second));
          } else if (isKey(b, "retries")) {
            spec.healthcheck->retries = Util::toUInt(AsString(b.second));
          } else if (isKey(b, "start_period") || isKey(b, "start-period")) {
            spec.healthcheck->startPeriodSec = Util::toUInt(AsString(b.second));
          } else {
            ERR("unknown element healthcheck/" << b.first << " in spec")
          }
        }
        if (spec.healthcheck->test.empty())
          ERR("healthcheck requires a 'test' command")
      } else {
        ERR("healthcheck must be a scalar (test command) or a map")
      }
    } else if (isKey(k, "depends")) {
      listOrScalarOnly(k.second, spec.depends, "depends");
    } else if (isKey(k, "base_container") || isKey(k, "base-container")) {
      // Base container cloning (§22): clone from existing running jail
      if (!k.second.IsMap())
        ERR("base_container must be a map with 'type' and 'name'")
      spec.baseContainer = std::make_unique<Spec::BaseContainer>();
      for (auto b : k.second) {
        if (isKey(b, "type"))
          scalar(b.second, spec.baseContainer->type, "base_container/type");
        else if (isKey(b, "name"))
          scalar(b.second, spec.baseContainer->name, "base_container/name");
        else
          ERR("unknown element base_container/" << b.first << " in spec")
      }
      if (spec.baseContainer->type.empty())
        spec.baseContainer->type = "jail"; // default
      if (spec.baseContainer->type != "jail")
        ERR("base_container/type must be 'jail' (only type currently supported)")
      if (spec.baseContainer->name.empty())
        ERR("base_container/name is required (jail name or JID)")
    } else if (isKey(k, "scripts")) {
      if (!k.second.IsMap())
        ERR("scripts must be a map")
        for (auto secScripts : k.second) {
          const auto section = AsString(secScripts.first);
          if (spec.scripts.find(section) != spec.scripts.end())
            ERR("duplicate 'scripts/" << section << "'")
          spec.scripts[AsString(secScripts.first)] = parseScriptsSection(section, secScripts.second);
        }
    } else {
      ERR("unknown top-level element '" << k.first << "' in spec")
    }
  }

  return spec;
}

Spec parseSpec(const std::string &fname) {
  return parseSpecFromNode(YAML::LoadFile(fname));
}

Spec parseSpecWithVars(const std::string &fname, const std::map<std::string, std::string> &vars) {
  if (vars.empty())
    return parseSpec(fname);
  // Read file, substitute variables, parse from string
  std::ifstream ifs(fname);
  if (!ifs.good())
    ERR("cannot open spec file: " << fname)
  std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
  content = substituteVars(content, vars);
  return parseSpecFromNode(YAML::Load(content));
}

Spec mergeSpecs(const Spec &base, const Spec &overlay) {
  Spec result = base;

  // Lists: append overlay items
  for (auto &v : overlay.baseKeep) result.baseKeep.push_back(v);
  for (auto &v : overlay.baseKeepWildcard) result.baseKeepWildcard.push_back(v);
  for (auto &v : overlay.baseRemove) result.baseRemove.push_back(v);
  for (auto &v : overlay.pkgInstall) result.pkgInstall.push_back(v);
  for (auto &v : overlay.pkgLocalOverride) result.pkgLocalOverride.push_back(v);
  for (auto &v : overlay.pkgAdd) result.pkgAdd.push_back(v);
  for (auto &v : overlay.pkgNuke) result.pkgNuke.push_back(v);
  for (auto &v : overlay.runServices) result.runServices.push_back(v);
  for (auto &v : overlay.dirsShare) result.dirsShare.push_back(v);
  for (auto &v : overlay.filesShare) result.filesShare.push_back(v);
  for (auto &v : overlay.zfsDatasets) result.zfsDatasets.push_back(v);
  for (auto &v : overlay.managedServices) result.managedServices.push_back(v);

  // Scalars: overlay wins if non-default
  if (!overlay.runCmdExecutable.empty()) {
    result.runCmdExecutable = overlay.runCmdExecutable;
    result.runCmdArgs = overlay.runCmdArgs;
  }
  if (overlay.encrypted) result.encrypted = overlay.encrypted;
  if (!overlay.encryptionMethod.empty()) result.encryptionMethod = overlay.encryptionMethod;
  if (!overlay.encryptionKeyformat.empty()) result.encryptionKeyformat = overlay.encryptionKeyformat;
  if (!overlay.encryptionCipher.empty()) result.encryptionCipher = overlay.encryptionCipher;
  if (overlay.allowSysvipc) result.allowSysvipc = true;
  if (overlay.allowMqueue) result.allowMqueue = true;
  if (overlay.ipcRawSocketsOverride) {
    result.ipcRawSocketsOverride = true;
    result.ipcRawSocketsValue = overlay.ipcRawSocketsValue;
  }
  if (overlay.enforceStatfs >= 0) result.enforceStatfs = overlay.enforceStatfs;
  if (overlay.allowQuotas) result.allowQuotas = true;
  if (overlay.allowSetHostname) result.allowSetHostname = true;
  if (overlay.allowChflags) result.allowChflags = true;
  if (overlay.allowMlock) result.allowMlock = true;

  // Maps: overlay wins for conflicts
  for (auto &opt : overlay.options) result.options[opt.first] = opt.second;
  for (auto &lim : overlay.limits) result.limits[lim.first] = lim.second;
  for (auto &s : overlay.scripts)
    for (auto &sc : s.second)
      result.scripts[s.first][sc.first] = sc.second;

  // Unique_ptrs: overlay wins if set
  if (overlay.dnsFilter) {
    result.dnsFilter = std::make_unique<Spec::DnsFilter>();
    *result.dnsFilter = *overlay.dnsFilter;
  }
  if (overlay.cowOptions) {
    result.cowOptions = std::make_unique<Spec::CowOptions>();
    *result.cowOptions = *overlay.cowOptions;
  }
  if (overlay.x11Options) {
    result.x11Options = std::make_unique<Spec::X11Options>();
    *result.x11Options = *overlay.x11Options;
  }
  if (overlay.clipboardOptions) {
    result.clipboardOptions = std::make_unique<Spec::ClipboardOptions>();
    *result.clipboardOptions = *overlay.clipboardOptions;
  }
  if (overlay.dbusOptions) {
    result.dbusOptions = std::make_unique<Spec::DbusOptions>();
    *result.dbusOptions = *overlay.dbusOptions;
  }
  if (overlay.socketProxy) {
    result.socketProxy = std::make_unique<Spec::SocketProxy>();
    *result.socketProxy = *overlay.socketProxy;
  }
  if (overlay.firewallPolicy) {
    result.firewallPolicy = std::make_unique<Spec::FirewallPolicy>();
    *result.firewallPolicy = *overlay.firewallPolicy;
  }
  if (overlay.securityAdvanced) {
    result.securityAdvanced = std::make_unique<Spec::SecurityAdvanced>();
    *result.securityAdvanced = *overlay.securityAdvanced;
  }
  if (overlay.terminalOptions) {
    result.terminalOptions = std::make_unique<Spec::TerminalOptions>();
    *result.terminalOptions = *overlay.terminalOptions;
  }
  if (overlay.guiOptions) {
    result.guiOptions = std::make_unique<Spec::GuiOptions>();
    *result.guiOptions = *overlay.guiOptions;
  }
  if (overlay.healthcheck) {
    result.healthcheck = std::make_unique<Spec::Healthcheck>();
    *result.healthcheck = *overlay.healthcheck;
  }
  if (overlay.baseContainer) {
    result.baseContainer = std::make_unique<Spec::BaseContainer>();
    *result.baseContainer = *overlay.baseContainer;
  }

  // depends: overlay replaces (not appends) since dependency graph should be explicit
  if (!overlay.depends.empty())
    result.depends = overlay.depends;

  return result;
}

