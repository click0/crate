// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_handlers.h"

#include "audit_per_user.h"
#include "ifconfig_ops.h"
#include "ipfw_ops.h"
#include "jail_query.h"
#include "pathnames.h"
#include "pfctl_ops.h"
#include "retune_pure.h"
#include "util.h"
#include "zfs_ops.h"

#include "../lib/audit_per_user_pure.h"
#include "../lib/privops_authz_pure.h"
#include "../lib/jid_owner_registry.h"

#include <iostream>

#include <ctime>

#include <sstream>

#ifdef __FreeBSD__
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/uio.h>
#endif
#include <cstdlib>
#include <cstring>
#include <errno.h>

#include <exception>
#include <string>
#include <vector>

namespace Crated {

using PrivOpsPure::Verb;
using PrivOpsWirePure::DispatchResult;

// --- handleSetRctl ---

DispatchResult handleSetRctl(const PrivOpsPure::SetRctlReq &r) {
  // The validator already enforced jid >= 1 and the key/value
  // shape. What it can't enforce: jail-still-running (a TOCTOU
  // window between client validate and daemon handler is
  // unavoidable). Re-check here.
  auto jail = JailQuery::getJailByJid((int)r.jid);
  if (!jail) {
    return {404, PrivOpsWirePure::formatHandlerError(
                  "jail_not_found",
                  "no running jail with jid " + std::to_string(r.jid))};
  }

  RetunePure::RctlPair pair{r.key, r.rawValue};
  auto argv = RetunePure::buildSetArgv((int)r.jid, pair);

  try {
    Util::execCommand(argv, "privops set_rctl");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("exec_failed", e.what())};
  }

  return {200, PrivOpsWirePure::formatSetRctlSuccess(r.jid, r.key, r.rawValue)};
}

// --- handleClearRctl ---

DispatchResult handleClearRctl(const PrivOpsPure::ClearRctlReq &r) {
  auto jail = JailQuery::getJailByJid((int)r.jid);
  if (!jail) {
    return {404, PrivOpsWirePure::formatHandlerError(
                  "jail_not_found",
                  "no running jail with jid " + std::to_string(r.jid))};
  }

  auto argv = RetunePure::buildClearArgv((int)r.jid, r.key);

  // Soft-fail clears are common in `crate retune` (the rule may
  // simply not exist yet). For the IPC surface we return the
  // operator's exec error verbatim so they can decide; the
  // dual semantics (idempotent vs. strict) can be added later
  // via a `?strict` flag if needed.
  try {
    Util::execCommand(argv, "privops clear_rctl");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("exec_failed", e.what())};
  }

  return {200, PrivOpsWirePure::formatClearRctlSuccess(r.jid, r.key)};
}

// --- handleAttachZfs / handleDetachZfs ---

DispatchResult handleAttachZfs(const PrivOpsPure::AttachZfsReq &r) {
  auto jail = JailQuery::getJailByJid((int)r.jid);
  if (!jail) {
    return {404, PrivOpsWirePure::formatHandlerError(
                  "jail_not_found",
                  "no running jail with jid " + std::to_string(r.jid))};
  }
  try {
    ZfsOps::jailDataset((int)r.jid, r.dataset);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("exec_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatAttachZfsSuccess(r.jid, r.dataset)};
}

DispatchResult handleDetachZfs(const PrivOpsPure::DetachZfsReq &r) {
  auto jail = JailQuery::getJailByJid((int)r.jid);
  if (!jail) {
    return {404, PrivOpsWirePure::formatHandlerError(
                  "jail_not_found",
                  "no running jail with jid " + std::to_string(r.jid))};
  }
  try {
    ZfsOps::unjailDataset((int)r.jid, r.dataset);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("exec_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatDetachZfsSuccess(r.jid, r.dataset)};
}

// --- handleMountNullfs / handleUnmountNullfs ---

DispatchResult handleMountNullfs(const PrivOpsPure::MountNullfsReq &r) {
#ifndef __FreeBSD__
  return {500, PrivOpsWirePure::formatHandlerError(
                "platform_unsupported",
                "nullfs mount only supported on FreeBSD")};
#else
  // Mirror lib/mount.cpp's nmount(2) iov pattern. Names get
  // strdup'd so we can free them after the call (nmount documents
  // the iov is consumed but doesn't promise pointer ownership).
  std::vector<iovec> iov;
  auto add = [&iov](const char *name, void *value, size_t valLen) {
    iov.push_back({::strdup(name), ::strlen(name) + 1});
    iov.push_back({value, valLen});
  };
  char errmsg[256] = {0};
  add("fstype", (void*)"nullfs", 7);
  add("fspath", (void*)r.target.c_str(), r.target.size() + 1);
  add("target", (void*)r.source.c_str(), r.source.size() + 1);
  add("errmsg", errmsg, sizeof(errmsg));
  int flags = r.readOnly ? MNT_RDONLY : 0;
  int res = ::nmount(iov.data(), iov.size(), flags);
  int savedErrno = errno;
  for (size_t i = 0; i < iov.size(); i += 2)
    ::free(iov[i].iov_base);
  if (res != 0) {
    std::string msg = ::strerror(savedErrno);
    if (errmsg[0]) { msg += " ("; msg += errmsg; msg += ")"; }
    return {500, PrivOpsWirePure::formatHandlerError("nmount_failed", msg)};
  }
  return {200, PrivOpsWirePure::formatMountNullfsSuccess(r.source, r.target, r.readOnly)};
#endif
}

DispatchResult handleUnmountNullfs(const PrivOpsPure::UnmountNullfsReq &r) {
#ifndef __FreeBSD__
  return {500, PrivOpsWirePure::formatHandlerError(
                "platform_unsupported",
                "nullfs unmount only supported on FreeBSD")};
#else
  int flags = r.force ? MNT_FORCE : 0;
  int res = ::unmount(r.target.c_str(), flags);
  if (res == -1) {
    return {500, PrivOpsWirePure::formatHandlerError("unmount_failed",
                                                     ::strerror(errno))};
  }
  return {200, PrivOpsWirePure::formatUnmountNullfsSuccess(r.target)};
#endif
}

// --- handleConfigureIface / handleTeardownIface ---

namespace {

// Compute the host-side epair half from an in-jail epair half name.
// "epair0b" -> "epair0a"; "epair17a" -> "epair17b". Returns empty
// string if the input doesn't look like an epair half name.
std::string computeEpairPair(const std::string &ifname) {
  // Pattern: "epair" + digits + 'a'|'b'
  if (ifname.size() < 7) return "";
  if (ifname.compare(0, 5, "epair") != 0) return "";
  char last = ifname.back();
  if (last != 'a' && last != 'b') return "";
  for (size_t i = 5; i < ifname.size() - 1; i++)
    if (ifname[i] < '0' || ifname[i] > '9') return "";
  std::string out = ifname;
  out.back() = (last == 'a') ? 'b' : 'a';
  return out;
}

} // anon

DispatchResult handleConfigureIface(const PrivOpsPure::ConfigureIfaceReq &r) {
  auto jail = JailQuery::getJailByJid((int)r.jid);
  if (!jail) {
    return {404, PrivOpsWirePure::formatHandlerError(
                  "jail_not_found",
                  "no running jail with jid " + std::to_string(r.jid))};
  }

  try {
    // 1. Move iface into the jail's vnet.
    IfconfigOps::moveToVnet(r.ifname, (int)r.jid);

    // 2. Inside the jail, set ipv4/ipv6/MAC and (only when at least
    // one of those was configured) bring the iface up. The
    // "move-only" mode (all three empty) intentionally leaves the
    // iface down so callers can DHCP/dhclient/static-config it
    // themselves later — added 0.9.20 so run_net.cpp can use this
    // verb for plain moveToVnet without disturbing downstream
    // configureDhcp / configureStaticIp.
    auto jidStr = std::to_string(r.jid);
    bool anyConfig = false;
    if (!r.ipv4Cidr.empty()) {
      Util::execCommand({CRATE_PATH_JEXEC, jidStr, CRATE_PATH_IFCONFIG,
                         r.ifname, "inet", r.ipv4Cidr},
                        "set ipv4 in jail");
      anyConfig = true;
    }
    if (!r.ipv6Cidr.empty()) {
      Util::execCommand({CRATE_PATH_JEXEC, jidStr, CRATE_PATH_IFCONFIG,
                         r.ifname, "inet6", r.ipv6Cidr},
                        "set ipv6 in jail");
      anyConfig = true;
    }
    if (!r.macAddr.empty()) {
      Util::execCommand({CRATE_PATH_JEXEC, jidStr, CRATE_PATH_IFCONFIG,
                         r.ifname, "ether", r.macAddr},
                        "set MAC in jail");
      anyConfig = true;
    }
    if (anyConfig) {
      Util::execCommand({CRATE_PATH_JEXEC, jidStr, CRATE_PATH_IFCONFIG,
                         r.ifname, "up"},
                        "bring iface up in jail");
    }

    // 3. Host-side: attach the pair-A half to the bridge.
    if (!r.bridge.empty()) {
      auto hostHalf = computeEpairPair(r.ifname);
      if (hostHalf.empty()) {
        return {400, PrivOpsWirePure::formatHandlerError(
                      "non_epair_with_bridge",
                      "bridge attach requires an epair-shaped ifname (got '"
                      + r.ifname + "')")};
      }
      IfconfigOps::bridgeAddMember(r.bridge, hostHalf);
    }
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("exec_failed", e.what())};
  }

  return {200, PrivOpsWirePure::formatConfigureIfaceSuccess(
                  r.jid, r.ifname, r.bridge, r.ipv4Cidr, r.ipv6Cidr, r.macAddr)};
}

DispatchResult handleTeardownIface(const PrivOpsPure::TeardownIfaceReq &r) {
  try {
    IfconfigOps::destroyInterface(r.ifname);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("destroy_failed",
                                                     e.what())};
  }
  return {200, PrivOpsWirePure::formatTeardownIfaceSuccess(r.ifname)};
}

// --- handleAddPfRule / handleRemovePfRule ---

DispatchResult handleAddPfRule(const PrivOpsPure::AddPfRuleReq &r) {
  try {
    PfctlOps::addRules(r.anchor, r.ruleText);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("pfctl_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatAddPfRuleSuccess(r.anchor, r.ruleText)};
}

DispatchResult handleRemovePfRule(const PrivOpsPure::RemovePfRuleReq &r) {
  // pfctl has no per-rule removal primitive; flush the anchor.
  // The request's ruleText field is currently ignored — kept in
  // the wire format for forward compat with a future per-rule
  // verb.
  try {
    PfctlOps::flushRules(r.anchor);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("pfctl_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatRemovePfRuleSuccess(r.anchor)};
}

// --- handleAddIpfwRule / handleRemoveIpfwRule ---

DispatchResult handleAddIpfwRule(const PrivOpsPure::AddIpfwRuleReq &r) {
  // Build `ipfw add <number> set <set> <action> <body>` argv
  // directly so we honour the `set` field (IpfwOps::addRule
  // doesn't take a set parameter — extending it would touch more
  // of the codebase than this verb justifies).
  try {
    std::vector<std::string> argv = {
      CRATE_PATH_IPFW, "add", std::to_string(r.number),
      "set", std::to_string(r.set),
      r.action,
    };
    std::istringstream iss(r.body);
    std::string token;
    while (iss >> token) argv.push_back(token);
    Util::execCommand(argv, "privops add_ipfw_rule");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("ipfw_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatAddIpfwRuleSuccess(
                  r.set, r.number, r.action, r.body)};
}

DispatchResult handleRemoveIpfwRule(const PrivOpsPure::RemoveIpfwRuleReq &r) {
  // ipfw delete is set-agnostic (rule numbers are unique
  // across the table). The set field is logged but doesn't
  // affect the kernel call.
  try {
    IpfwOps::deleteRule(r.number);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("ipfw_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatRemoveIpfwRuleSuccess(r.set, r.number)};
}

// --- handleCreateJail / handleDestroyJail ---

DispatchResult handleCreateJail(const PrivOpsPure::CreateJailReq &r) {
  // `jail -c name=X path=Y host.hostname=H [vnet] [params...] persist`
  // The privops layer creates only the jail registration. ZFS
  // attach, mount, iface config are operator-driven via the other
  // verbs.
  std::vector<std::string> argv = {CRATE_PATH_JAIL, "-c"};
  argv.push_back("name=" + r.name);
  argv.push_back("path=" + r.path);
  if (!r.hostname.empty())
    argv.push_back("host.hostname=" + r.hostname);
  if (r.vnet)
    argv.push_back("vnet");
  // parameters: split on whitespace into separate argv entries.
  // Validator already restricts to a single line and forbids shell
  // metas so this split is safe.
  if (!r.parameters.empty()) {
    std::istringstream iss(r.parameters);
    std::string token;
    while (iss >> token) argv.push_back(token);
  }
  argv.push_back("persist");

  try {
    Util::execCommand(argv, "privops create_jail");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("jail_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatCreateJailSuccess(r.name, r.path)};
}

DispatchResult handleDestroyJail(const PrivOpsPure::DestroyJailReq &r) {
  // `jail -r NAME` is graceful; `jail -R NAME` is force-kill.
  std::vector<std::string> argv = {
    CRATE_PATH_JAIL, r.force ? "-R" : "-r", r.name,
  };
  try {
    Util::execCommand(argv, "privops destroy_jail");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("jail_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatDestroyJailSuccess(r.name)};
}

// --- handleSetIfaceUp / handleDisableIfaceOffload (0.9.23) ---

DispatchResult handleSetIfaceUp(const PrivOpsPure::SetIfaceUpReq &r) {
  try {
    IfconfigOps::setUp(r.ifname);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("ifconfig_failed",
                                                     e.what())};
  }
  return {200, PrivOpsWirePure::formatSetIfaceUpSuccess(r.ifname)};
}

DispatchResult handleDisableIfaceOffload(const PrivOpsPure::DisableIfaceOffloadReq &r) {
  try {
    IfconfigOps::disableOffload(r.ifname);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("ifconfig_failed",
                                                     e.what())};
  }
  return {200, PrivOpsWirePure::formatDisableIfaceOffloadSuccess(r.ifname)};
}

// --- handleBridgeAddMember / handleBridgeDelMember (0.9.24) ---

DispatchResult handleBridgeAddMember(const PrivOpsPure::BridgeAddMemberReq &r) {
  try {
    IfconfigOps::bridgeAddMember(r.bridge, r.member);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("ifconfig_failed",
                                                     e.what())};
  }
  return {200, PrivOpsWirePure::formatBridgeAddMemberSuccess(r.bridge, r.member)};
}

DispatchResult handleBridgeDelMember(const PrivOpsPure::BridgeDelMemberReq &r) {
  try {
    IfconfigOps::bridgeDelMember(r.bridge, r.member);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("ifconfig_failed",
                                                     e.what())};
  }
  return {200, PrivOpsWirePure::formatBridgeDelMemberSuccess(r.bridge, r.member)};
}

// --- handleSetIfaceInetAddr (0.9.25) ---

DispatchResult handleSetIfaceInetAddr(const PrivOpsPure::SetIfaceInetAddrReq &r) {
  try {
    IfconfigOps::setInetAddr(r.ifname, r.addr, (int)r.prefixLen);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("ifconfig_failed",
                                                     e.what())};
  }
  return {200, PrivOpsWirePure::formatSetIfaceInetAddrSuccess(
                  r.ifname, r.addr, r.prefixLen)};
}

// --- handleCreateEpair (0.9.26) ---

DispatchResult handleCreateEpair(const PrivOpsPure::CreateEpairReq &/*r*/) {
  std::pair<std::string, std::string> pair;
  try {
    pair = IfconfigOps::createEpair();
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("ifconfig_failed",
                                                     e.what())};
  }
  return {200, PrivOpsWirePure::formatCreateEpairSuccess(pair.first,
                                                          pair.second)};
}

// --- handleSetLoginclassRctl / handleClearLoginclassRctl (0.9.28) ---

DispatchResult handleSetLoginclassRctl(const PrivOpsPure::SetLoginclassRctlReq &r) {
  // Build `rctl -a loginclass:<name>:<key>:deny=<value>` argv.
  // Mirrors handleSetRctl (0.9.2) but with loginclass subject.
  std::string rule = "loginclass:" + r.loginclass + ":" + r.key
                   + ":deny=" + r.rawValue;
  try {
    Util::execCommand({CRATE_PATH_RCTL, "-a", rule},
                      "privops set_loginclass_rctl");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("exec_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatSetLoginclassRctlSuccess(
                  r.loginclass, r.key, r.rawValue)};
}

DispatchResult handleClearLoginclassRctl(const PrivOpsPure::ClearLoginclassRctlReq &r) {
  // `rctl -r loginclass:<name>:<key>:deny` — symmetric remove.
  std::string subject = "loginclass:" + r.loginclass + ":" + r.key + ":deny";
  try {
    Util::execCommand({CRATE_PATH_RCTL, "-r", subject},
                      "privops clear_loginclass_rctl");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("exec_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatClearLoginclassRctlSuccess(
                  r.loginclass, r.key)};
}

// --- handleReclaimIfaceFromVnet (1.0.5) ---

DispatchResult handleReclaimIfaceFromVnet(const PrivOpsPure::ReclaimIfaceFromVnetReq &r) {
  try {
    IfconfigOps::moveFromVnet(r.ifname, r.jailName);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("ifconfig_failed",
                                                     e.what())};
  }
  return {200, PrivOpsWirePure::formatReclaimIfaceFromVnetSuccess(
                  r.ifname, r.jailName)};
}

// --- handleFlushPfAnchor (1.1.0) ---

DispatchResult handleFlushPfAnchor(const PrivOpsPure::FlushPfAnchorReq &r) {
  try {
    PfctlOps::flushRules(r.anchor);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("pfctl_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatFlushPfAnchorSuccess(r.anchor)};
}

// --- handleQueryJailRctl (1.1.1) ---

DispatchResult handleQueryJailRctl(const PrivOpsPure::QueryJailRctlReq &r) {
  std::string output;
  try {
    output = Util::execCommandGetOutput(
      {CRATE_PATH_RCTL, "-u", "jail:" + std::to_string(r.jid)},
      "privops query_jail_rctl");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("rctl_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatQueryJailRctlSuccess(r.jid, output)};
}

// --- handleConfigureIpfwNat (1.1.8) ---

DispatchResult handleConfigureIpfwNat(const PrivOpsPure::ConfigureIpfwNatReq &r) {
  std::vector<std::string> argv = {
    CRATE_PATH_IPFW, "nat", std::to_string(r.number), "config",
  };
  std::istringstream iss(r.config);
  std::string token;
  while (iss >> token) argv.push_back(token);
  try {
    Util::execCommand(argv, "privops configure_ipfw_nat");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("ipfw_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatConfigureIpfwNatSuccess(r.number)};
}

// --- handleSetJailCpuset (1.1.9) ---

DispatchResult handleSetJailCpuset(const PrivOpsPure::SetJailCpusetReq &r) {
  try {
    Util::execCommand(
      {CRATE_PATH_CPUSET, "-l", r.cpuset, "-j", std::to_string(r.jid)},
      "privops set_jail_cpuset");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("cpuset_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatSetJailCpusetSuccess(r.jid, r.cpuset)};
}

// --- handleApplyDevfsRuleset (1.1.10) ---

DispatchResult handleApplyDevfsRuleset(const PrivOpsPure::ApplyDevfsRulesetReq &r) {
  std::string rulesetStr = std::to_string(r.ruleset);
  try {
    Util::execCommand(
      {CRATE_PATH_DEVFS, "-m", r.mountPath, "ruleset", rulesetStr},
      "privops apply_devfs_ruleset (set)");
    Util::execCommand(
      {CRATE_PATH_DEVFS, "-m", r.mountPath, "rule", "applyset"},
      "privops apply_devfs_ruleset (applyset)");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("devfs_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatApplyDevfsRulesetSuccess(r.mountPath, r.ruleset)};
}

// --- handleAddDevfsUnhideRule (1.1.10) ---

DispatchResult handleAddDevfsUnhideRule(const PrivOpsPure::AddDevfsUnhideRuleReq &r) {
  try {
    Util::execCommand(
      {CRATE_PATH_DEVFS, "-m", r.mountPath,
       "rule", "add", "path", r.pathPattern, "unhide"},
      "privops add_devfs_unhide_rule (add)");
    Util::execCommand(
      {CRATE_PATH_DEVFS, "-m", r.mountPath, "rule", "applyset"},
      "privops add_devfs_unhide_rule (applyset)");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("devfs_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatAddDevfsUnhideRuleSuccess(
                  r.mountPath, r.pathPattern)};
}

// --- handleSignalJail (1.1.11) ---

DispatchResult handleSignalJail(const PrivOpsPure::SignalJailReq &r) {
  // `jexec <jid> /bin/kill -<signal> -1` — signal every process
  // in the jail. The signal name is whitelisted by the validator.
  try {
    Util::execCommand(
      {CRATE_PATH_JEXEC, std::to_string(r.jid),
       "/bin/kill", "-" + r.signal, "-1"},
      "privops signal_jail");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("jexec_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatSignalJailSuccess(r.jid, r.signal)};
}

// --- Top-level dispatcher ---

namespace {

// Best-effort per-user audit tail. No-op when uid==0 or rootless
// is off (i.e. legacy single-tenant flow). Called after the
// dispatcher computes its result, just before returning.
void maybeWritePerUserAudit(bool rootlessPerUser, uint32_t uid,
                            Verb v, int status) {
  if (!rootlessPerUser || uid == 0) return;
  AuditPerUserPure::Record r;
  r.timestamp = (long)std::time(nullptr);
  r.uid       = uid;
  r.verb      = PrivOpsPure::verbName(v);
  r.status    = status;
  appendPerUserAuditLine(uid, AuditPerUserPure::formatLine(r));
}

// 0.9.29: process-global RCTL umbrella config. Set once at daemon
// startup via setUmbrellaConfig(); read by maybeApplyUmbrella()
// after a successful create_jail privops invocation. Safe for
// concurrent reads after the one-time write at startup.
std::vector<std::pair<std::string, std::string>> g_umbrellaRules;

// 1.1.12: process-global per-user namespacing config, set once at
// startup via setPerUserAuthzConfig(). Read by dispatchPrivOpFromMap's
// authorize-before-dispatch gate to derive the caller's per-user env
// (ZFS prefix, loginclass) from the getpeereid uid. Safe for concurrent
// reads after the one-time write at startup.
PerUserEnvPure::Config g_perUserAuthzCfg;

// 1.1.13: process-global jid->owner registry pointer. The instance is
// owned by daemon/main.cpp and outlives every request. nullptr disables
// the gate (dispatcher falls back to the 1.1.12 behavior — Allow for
// jid/name-scoped verbs). JidOwnerRegistry has its own internal mutex,
// so multiple dispatcher threads can read/write safely.
::JidOwnerRegistry *g_jidOwnerRegistry = nullptr;

// Update the jid->owner registry after a successful create_jail /
// destroy_jail dispatch (libnv path only — uid==0 on HTTP means we
// don't know which operator to credit, so the registry stays untouched).
// Errors persisting the registry are logged but do NOT fail the verb:
// the jail is already up (or already gone), and losing the registry
// entry only weakens authz for *this* jail until the next restart's
// bootstrap. Fail-soft on bookkeeping is preferable to leaving an
// orphan jail because we couldn't write a tsv line.
void maybeUpdateJidOwnerRegistry(Verb v, uint32_t uid,
                                  const PrivOpsNvPure::FieldMap &m,
                                  int status) {
  if (!g_jidOwnerRegistry || uid == 0) return;
  if (status < 200 || status >= 300)  return;

  auto field = [&m](const char *key) -> std::string {
    auto it = m.find(key);
    return it == m.end() ? std::string() : it->second;
  };

  if (v == Verb::CreateJail) {
    std::string name = field("name");
    std::string path = field("path");
    if (name.empty()) return;          // validator already rejected this
    // jail(8) just assigned a jid; resolve it via libjail. If lookup
    // fails (race, deleted between create and lookup) skip the record —
    // the next destroy_jail will be a no-op-forget, which is harmless.
    auto j = JailQuery::getJailByName(name);
    if (!j) {
      std::cerr << "privops: created jail '" << name
                << "' vanished before jid lookup — registry not updated"
                << std::endl;
      return;
    }
    try {
      g_jidOwnerRegistry->recordCreate(static_cast<unsigned>(j->jid),
                                       uid, name, path);
    } catch (const std::exception &e) {
      std::cerr << "privops: jid_owner_registry recordCreate(" << name
                << "): " << e.what() << std::endl;
    }
  } else if (v == Verb::DestroyJail) {
    std::string name = field("name");
    if (name.empty()) return;
    try {
      g_jidOwnerRegistry->forgetByName(name);
    } catch (const std::exception &e) {
      std::cerr << "privops: jid_owner_registry forgetByName(" << name
                << "): " << e.what() << std::endl;
    }
  }
}

// Apply umbrella rules to the operator's `crate-<uid>` loginclass
// after a successful create_jail. Only fires when:
//   - operator's uid is known (uid > 0; libnv path supplies it,
//     HTTP path always has uid=0 → no-op)
//   - the verb was create_jail and returned 2xx
//   - g_umbrellaRules is non-empty (operator opted in via
//     `rctl_umbrella:` in crated.conf)
//
// Best-effort: rctl(8) failures are logged to stderr but do NOT
// fail the create_jail response — the jail is already up; losing
// an umbrella rule is a quota gap, not a correctness break.
void maybeApplyUmbrella(Verb v, uint32_t uid, int status) {
  if (v != Verb::CreateJail) return;
  if (uid == 0 || status < 200 || status >= 300) return;
  if (g_umbrellaRules.empty()) return;
  std::string loginclass = "crate-" + std::to_string(uid);
  for (const auto &kv : g_umbrellaRules) {
    std::string rule = "loginclass:" + loginclass + ":" + kv.first
                     + ":deny=" + kv.second;
    try {
      Util::execCommand({CRATE_PATH_RCTL, "-a", rule},
                        "privops umbrella");
    } catch (const std::exception &e) {
      std::fprintf(stderr,
          "privops_handlers: umbrella rule '%s' for uid %u failed: %s\n",
          rule.c_str(), (unsigned)uid, e.what());
    }
  }
}

} // anon

DispatchResult dispatchPrivOp(Verb v, const std::string &body,
                              bool rootlessPerUser, uint32_t operatorUid) {
  DispatchResult result = [&]() -> DispatchResult {
  switch (v) {
    case Verb::SetRctl: {
      PrivOpsPure::SetRctlReq r;
      if (auto e = PrivOpsWirePure::parseSetRctl(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSetRctl(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSetRctl(r);
    }
    case Verb::ClearRctl: {
      PrivOpsPure::ClearRctlReq r;
      if (auto e = PrivOpsWirePure::parseClearRctl(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateClearRctl(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleClearRctl(r);
    }
    case Verb::AttachZfs: {
      PrivOpsPure::AttachZfsReq r;
      if (auto e = PrivOpsWirePure::parseAttachZfs(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateAttachZfs(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleAttachZfs(r);
    }
    case Verb::DetachZfs: {
      PrivOpsPure::DetachZfsReq r;
      if (auto e = PrivOpsWirePure::parseDetachZfs(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateDetachZfs(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleDetachZfs(r);
    }
    case Verb::MountNullfs: {
      PrivOpsPure::MountNullfsReq r;
      if (auto e = PrivOpsWirePure::parseMountNullfs(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateMountNullfs(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleMountNullfs(r);
    }
    case Verb::UnmountNullfs: {
      PrivOpsPure::UnmountNullfsReq r;
      if (auto e = PrivOpsWirePure::parseUnmountNullfs(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateUnmountNullfs(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleUnmountNullfs(r);
    }
    case Verb::ConfigureIface: {
      PrivOpsPure::ConfigureIfaceReq r;
      if (auto e = PrivOpsWirePure::parseConfigureIface(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateConfigureIface(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleConfigureIface(r);
    }
    case Verb::TeardownIface: {
      PrivOpsPure::TeardownIfaceReq r;
      if (auto e = PrivOpsWirePure::parseTeardownIface(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateTeardownIface(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleTeardownIface(r);
    }
    case Verb::AddPfRule: {
      PrivOpsPure::AddPfRuleReq r;
      if (auto e = PrivOpsWirePure::parseAddPfRule(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateAddPfRule(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleAddPfRule(r);
    }
    case Verb::RemovePfRule: {
      PrivOpsPure::RemovePfRuleReq r;
      if (auto e = PrivOpsWirePure::parseRemovePfRule(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateRemovePfRule(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleRemovePfRule(r);
    }
    case Verb::AddIpfwRule: {
      PrivOpsPure::AddIpfwRuleReq r;
      if (auto e = PrivOpsWirePure::parseAddIpfwRule(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateAddIpfwRule(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleAddIpfwRule(r);
    }
    case Verb::RemoveIpfwRule: {
      PrivOpsPure::RemoveIpfwRuleReq r;
      if (auto e = PrivOpsWirePure::parseRemoveIpfwRule(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateRemoveIpfwRule(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleRemoveIpfwRule(r);
    }
    case Verb::CreateJail: {
      PrivOpsPure::CreateJailReq r;
      if (auto e = PrivOpsWirePure::parseCreateJail(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateCreateJail(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleCreateJail(r);
    }
    case Verb::DestroyJail: {
      PrivOpsPure::DestroyJailReq r;
      if (auto e = PrivOpsWirePure::parseDestroyJail(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateDestroyJail(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleDestroyJail(r);
    }
    case Verb::SetIfaceUp: {
      PrivOpsPure::SetIfaceUpReq r;
      if (auto e = PrivOpsWirePure::parseSetIfaceUp(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSetIfaceUp(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSetIfaceUp(r);
    }
    case Verb::DisableIfaceOffload: {
      PrivOpsPure::DisableIfaceOffloadReq r;
      if (auto e = PrivOpsWirePure::parseDisableIfaceOffload(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateDisableIfaceOffload(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleDisableIfaceOffload(r);
    }
    case Verb::BridgeAddMember: {
      PrivOpsPure::BridgeAddMemberReq r;
      if (auto e = PrivOpsWirePure::parseBridgeAddMember(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateBridgeAddMember(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleBridgeAddMember(r);
    }
    case Verb::BridgeDelMember: {
      PrivOpsPure::BridgeDelMemberReq r;
      if (auto e = PrivOpsWirePure::parseBridgeDelMember(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateBridgeDelMember(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleBridgeDelMember(r);
    }
    case Verb::SetIfaceInetAddr: {
      PrivOpsPure::SetIfaceInetAddrReq r;
      if (auto e = PrivOpsWirePure::parseSetIfaceInetAddr(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSetIfaceInetAddr(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSetIfaceInetAddr(r);
    }
    case Verb::CreateEpair: {
      PrivOpsPure::CreateEpairReq r;
      if (auto e = PrivOpsWirePure::parseCreateEpair(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateCreateEpair(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleCreateEpair(r);
    }
    case Verb::SetLoginclassRctl: {
      PrivOpsPure::SetLoginclassRctlReq r;
      if (auto e = PrivOpsWirePure::parseSetLoginclassRctl(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSetLoginclassRctl(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSetLoginclassRctl(r);
    }
    case Verb::ClearLoginclassRctl: {
      PrivOpsPure::ClearLoginclassRctlReq r;
      if (auto e = PrivOpsWirePure::parseClearLoginclassRctl(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateClearLoginclassRctl(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleClearLoginclassRctl(r);
    }
    case Verb::ReclaimIfaceFromVnet: {
      PrivOpsPure::ReclaimIfaceFromVnetReq r;
      if (auto e = PrivOpsWirePure::parseReclaimIfaceFromVnet(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateReclaimIfaceFromVnet(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleReclaimIfaceFromVnet(r);
    }
    case Verb::FlushPfAnchor: {
      PrivOpsPure::FlushPfAnchorReq r;
      if (auto e = PrivOpsWirePure::parseFlushPfAnchor(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateFlushPfAnchor(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleFlushPfAnchor(r);
    }
    case Verb::QueryJailRctl: {
      PrivOpsPure::QueryJailRctlReq r;
      if (auto e = PrivOpsWirePure::parseQueryJailRctl(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateQueryJailRctl(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleQueryJailRctl(r);
    }
    case Verb::ConfigureIpfwNat: {
      PrivOpsPure::ConfigureIpfwNatReq r;
      if (auto e = PrivOpsWirePure::parseConfigureIpfwNat(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateConfigureIpfwNat(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleConfigureIpfwNat(r);
    }
    case Verb::SetJailCpuset: {
      PrivOpsPure::SetJailCpusetReq r;
      if (auto e = PrivOpsWirePure::parseSetJailCpuset(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSetJailCpuset(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSetJailCpuset(r);
    }
    case Verb::ApplyDevfsRuleset: {
      PrivOpsPure::ApplyDevfsRulesetReq r;
      if (auto e = PrivOpsWirePure::parseApplyDevfsRuleset(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateApplyDevfsRuleset(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleApplyDevfsRuleset(r);
    }
    case Verb::AddDevfsUnhideRule: {
      PrivOpsPure::AddDevfsUnhideRuleReq r;
      if (auto e = PrivOpsWirePure::parseAddDevfsUnhideRule(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateAddDevfsUnhideRule(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleAddDevfsUnhideRule(r);
    }
    case Verb::SignalJail: {
      PrivOpsPure::SignalJailReq r;
      if (auto e = PrivOpsWirePure::parseSignalJail(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSignalJail(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSignalJail(r);
    }
    default:
      return PrivOpsWirePure::parseValidateAndDispatch(v, body);
  }
  }();
  // 0.9.13: per-user audit tail (best-effort; no-op for uid=0 /
  // rootless off).
  maybeWritePerUserAudit(rootlessPerUser, operatorUid, v, result.status);
  return result;
}

// --- dispatchPrivOpFromMap (0.9.14, libnv transport) ---

DispatchResult dispatchPrivOpFromMap(const PrivOpsNvPure::FieldMap &m,
                                     bool rootlessPerUser,
                                     uint32_t operatorUid) {
  Verb v = PrivOpsNvPure::extractVerb(m);

  // 1.1.12 + 1.1.13: authorize-before-dispatch. The libnv transport
  // carries a real peer uid (getpeereid); when rootless per-user is on,
  // every verb that has a robust ownership signal in the request is
  // gated:
  //   - dataset (attach_zfs/detach_zfs) — outside the caller's ZFS
  //     prefix -> 403 (1.1.12)
  //   - loginclass (set_loginclass_rctl/clear_loginclass_rctl) — not
  //     the caller's crate-<uid> umbrella -> 403 (1.1.12)
  //   - jid (set_rctl/clear_rctl/set_jail_cpuset/query_jail_rctl/
  //     signal_jail) — owned by a different uid in the registry
  //     -> 403 (1.1.13)
  //   - jail name (destroy_jail) — owned by a different uid in the
  //     registry -> 403 (1.1.13)
  // Unknown jid/name in the registry (no entry) is allowed: that
  // covers jails created before 1.1.13. The HTTP path (uid==0,
  // admin-only) skips the gate by design and stays host-wide.
  if (rootlessPerUser && operatorUid > 0) {
    const PerUserEnvPure::Env env =
        PerUserEnvPure::composeForUid(g_perUserAuthzCfg, operatorUid).env;
    auto field = [&m](const char *key) -> std::string {
      auto it = m.find(key);
      return it == m.end() ? std::string() : it->second;
    };
    PrivOpsAuthzPure::Request req;
    req.dataset    = field("dataset");
    req.loginclass = field("loginclass");
    req.jailName   = field("name");
    {
      // jid arrives as a decimal string in the libnv FieldMap; parse
      // defensively. The downstream validator will catch a missing
      // or out-of-range jid for the actual verb call — here we just
      // need a number to look up in the registry (0 = "not set" =
      // no jid-scoped gate fires).
      auto jidStr = field("jid");
      if (!jidStr.empty()) {
        try { req.jid = static_cast<unsigned>(std::stoul(jidStr)); }
        catch (...) { req.jid = 0; }
      }
    }
    // 1.1.14: path-scoped verbs. The field name differs per verb —
    // mount/unmount nullfs use "target" (the mount destination, which
    // must lie under an owned jail); devfs verbs use "mount_path"
    // (the jail's /dev mount). Empty for verbs that don't carry a
    // path arg — checkOwnedPath then short-circuits to Allow.
    switch (v) {
      case Verb::MountNullfs:
      case Verb::UnmountNullfs:        req.path = field("target");     break;
      case Verb::ApplyDevfsRuleset:
      case Verb::AddDevfsUnhideRule:   req.path = field("mount_path"); break;
      // 1.1.15: create_jail's path argument is checked against the
      // caller's per-user path prefix (env.pathPrefix); not a registry
      // lookup (the jail doesn't exist yet).
      case Verb::CreateJail:           req.path = field("path");       break;
      default:                                                          break;
    }
    PrivOpsAuthzPure::OwnerLookup lookup = g_jidOwnerRegistry
        ? g_jidOwnerRegistry->makeLookup()
        : PrivOpsAuthzPure::nullLookup();
    PrivOpsAuthzPure::Decision dec =
        PrivOpsAuthzPure::authorize(v, req, env, lookup);
    if (dec != PrivOpsAuthzPure::Decision::Allow) {
      return {403, PrivOpsWirePure::formatHandlerError(
                       "forbidden", PrivOpsAuthzPure::decisionReason(dec))};
    }
  }

  DispatchResult result = [&]() -> DispatchResult {
  switch (v) {
    case Verb::SetRctl: {
      PrivOpsPure::SetRctlReq r;
      if (auto e = PrivOpsNvPure::parseSetRctl(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSetRctl(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSetRctl(r);
    }
    case Verb::ClearRctl: {
      PrivOpsPure::ClearRctlReq r;
      if (auto e = PrivOpsNvPure::parseClearRctl(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateClearRctl(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleClearRctl(r);
    }
    case Verb::AttachZfs: {
      PrivOpsPure::AttachZfsReq r;
      if (auto e = PrivOpsNvPure::parseAttachZfs(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateAttachZfs(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleAttachZfs(r);
    }
    case Verb::DetachZfs: {
      PrivOpsPure::DetachZfsReq r;
      if (auto e = PrivOpsNvPure::parseDetachZfs(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateDetachZfs(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleDetachZfs(r);
    }
    case Verb::MountNullfs: {
      PrivOpsPure::MountNullfsReq r;
      if (auto e = PrivOpsNvPure::parseMountNullfs(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateMountNullfs(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleMountNullfs(r);
    }
    case Verb::UnmountNullfs: {
      PrivOpsPure::UnmountNullfsReq r;
      if (auto e = PrivOpsNvPure::parseUnmountNullfs(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateUnmountNullfs(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleUnmountNullfs(r);
    }
    case Verb::ConfigureIface: {
      PrivOpsPure::ConfigureIfaceReq r;
      if (auto e = PrivOpsNvPure::parseConfigureIface(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateConfigureIface(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleConfigureIface(r);
    }
    case Verb::TeardownIface: {
      PrivOpsPure::TeardownIfaceReq r;
      if (auto e = PrivOpsNvPure::parseTeardownIface(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateTeardownIface(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleTeardownIface(r);
    }
    case Verb::AddPfRule: {
      PrivOpsPure::AddPfRuleReq r;
      if (auto e = PrivOpsNvPure::parseAddPfRule(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateAddPfRule(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleAddPfRule(r);
    }
    case Verb::RemovePfRule: {
      PrivOpsPure::RemovePfRuleReq r;
      if (auto e = PrivOpsNvPure::parseRemovePfRule(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateRemovePfRule(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleRemovePfRule(r);
    }
    case Verb::AddIpfwRule: {
      PrivOpsPure::AddIpfwRuleReq r;
      if (auto e = PrivOpsNvPure::parseAddIpfwRule(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateAddIpfwRule(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleAddIpfwRule(r);
    }
    case Verb::RemoveIpfwRule: {
      PrivOpsPure::RemoveIpfwRuleReq r;
      if (auto e = PrivOpsNvPure::parseRemoveIpfwRule(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateRemoveIpfwRule(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleRemoveIpfwRule(r);
    }
    case Verb::CreateJail: {
      PrivOpsPure::CreateJailReq r;
      if (auto e = PrivOpsNvPure::parseCreateJail(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateCreateJail(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleCreateJail(r);
    }
    case Verb::DestroyJail: {
      PrivOpsPure::DestroyJailReq r;
      if (auto e = PrivOpsNvPure::parseDestroyJail(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateDestroyJail(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleDestroyJail(r);
    }
    case Verb::SetIfaceUp: {
      PrivOpsPure::SetIfaceUpReq r;
      if (auto e = PrivOpsNvPure::parseSetIfaceUp(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSetIfaceUp(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSetIfaceUp(r);
    }
    case Verb::DisableIfaceOffload: {
      PrivOpsPure::DisableIfaceOffloadReq r;
      if (auto e = PrivOpsNvPure::parseDisableIfaceOffload(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateDisableIfaceOffload(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleDisableIfaceOffload(r);
    }
    case Verb::BridgeAddMember: {
      PrivOpsPure::BridgeAddMemberReq r;
      if (auto e = PrivOpsNvPure::parseBridgeAddMember(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateBridgeAddMember(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleBridgeAddMember(r);
    }
    case Verb::BridgeDelMember: {
      PrivOpsPure::BridgeDelMemberReq r;
      if (auto e = PrivOpsNvPure::parseBridgeDelMember(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateBridgeDelMember(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleBridgeDelMember(r);
    }
    case Verb::SetIfaceInetAddr: {
      PrivOpsPure::SetIfaceInetAddrReq r;
      if (auto e = PrivOpsNvPure::parseSetIfaceInetAddr(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSetIfaceInetAddr(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSetIfaceInetAddr(r);
    }
    case Verb::CreateEpair: {
      PrivOpsPure::CreateEpairReq r;
      if (auto e = PrivOpsNvPure::parseCreateEpair(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateCreateEpair(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleCreateEpair(r);
    }
    case Verb::SetLoginclassRctl: {
      PrivOpsPure::SetLoginclassRctlReq r;
      if (auto e = PrivOpsNvPure::parseSetLoginclassRctl(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSetLoginclassRctl(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSetLoginclassRctl(r);
    }
    case Verb::ClearLoginclassRctl: {
      PrivOpsPure::ClearLoginclassRctlReq r;
      if (auto e = PrivOpsNvPure::parseClearLoginclassRctl(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateClearLoginclassRctl(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleClearLoginclassRctl(r);
    }
    case Verb::ReclaimIfaceFromVnet: {
      PrivOpsPure::ReclaimIfaceFromVnetReq r;
      if (auto e = PrivOpsNvPure::parseReclaimIfaceFromVnet(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateReclaimIfaceFromVnet(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleReclaimIfaceFromVnet(r);
    }
    case Verb::FlushPfAnchor: {
      PrivOpsPure::FlushPfAnchorReq r;
      if (auto e = PrivOpsNvPure::parseFlushPfAnchor(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateFlushPfAnchor(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleFlushPfAnchor(r);
    }
    case Verb::QueryJailRctl: {
      PrivOpsPure::QueryJailRctlReq r;
      if (auto e = PrivOpsNvPure::parseQueryJailRctl(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateQueryJailRctl(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleQueryJailRctl(r);
    }
    case Verb::ConfigureIpfwNat: {
      PrivOpsPure::ConfigureIpfwNatReq r;
      if (auto e = PrivOpsNvPure::parseConfigureIpfwNat(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateConfigureIpfwNat(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleConfigureIpfwNat(r);
    }
    case Verb::SetJailCpuset: {
      PrivOpsPure::SetJailCpusetReq r;
      if (auto e = PrivOpsNvPure::parseSetJailCpuset(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSetJailCpuset(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSetJailCpuset(r);
    }
    case Verb::ApplyDevfsRuleset: {
      PrivOpsPure::ApplyDevfsRulesetReq r;
      if (auto e = PrivOpsNvPure::parseApplyDevfsRuleset(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateApplyDevfsRuleset(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleApplyDevfsRuleset(r);
    }
    case Verb::AddDevfsUnhideRule: {
      PrivOpsPure::AddDevfsUnhideRuleReq r;
      if (auto e = PrivOpsNvPure::parseAddDevfsUnhideRule(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateAddDevfsUnhideRule(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleAddDevfsUnhideRule(r);
    }
    case Verb::SignalJail: {
      PrivOpsPure::SignalJailReq r;
      if (auto e = PrivOpsNvPure::parseSignalJail(m, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSignalJail(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSignalJail(r);
    }
    case Verb::Unknown:
      return {404,
              std::string("{\"error\":\"unknown or missing 'verb' field\"}")};
  }
  return {404,
          std::string("{\"error\":\"unknown or missing 'verb' field\"}")};
  }();
  maybeWritePerUserAudit(rootlessPerUser, operatorUid, v, result.status);
  maybeApplyUmbrella(v, operatorUid, result.status);
  maybeUpdateJidOwnerRegistry(v, operatorUid, m, result.status);
  return result;
}

// 0.9.29: setter for the process-global umbrella config. daemon/main.cpp
// calls this once at startup with the parsed `rctl_umbrella` block.
void setUmbrellaConfig(const std::vector<std::pair<std::string, std::string>> &rules) {
  g_umbrellaRules = rules;
}

void setPerUserAuthzConfig(const PerUserEnvPure::Config &cfg) {
  g_perUserAuthzCfg = cfg;
}

void setJidOwnerRegistry(::JidOwnerRegistry *registry) {
  g_jidOwnerRegistry = registry;
}

} // namespace Crated
