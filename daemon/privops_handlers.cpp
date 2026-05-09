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

    // 2. Inside the jail, set ipv4/ipv6/MAC and bring up.
    auto jidStr = std::to_string(r.jid);
    if (!r.ipv4Cidr.empty()) {
      Util::execCommand({CRATE_PATH_JEXEC, jidStr, CRATE_PATH_IFCONFIG,
                         r.ifname, "inet", r.ipv4Cidr},
                        "set ipv4 in jail");
    }
    if (!r.ipv6Cidr.empty()) {
      Util::execCommand({CRATE_PATH_JEXEC, jidStr, CRATE_PATH_IFCONFIG,
                         r.ifname, "inet6", r.ipv6Cidr},
                        "set ipv6 in jail");
    }
    if (!r.macAddr.empty()) {
      Util::execCommand({CRATE_PATH_JEXEC, jidStr, CRATE_PATH_IFCONFIG,
                         r.ifname, "ether", r.macAddr},
                        "set MAC in jail");
    }
    Util::execCommand({CRATE_PATH_JEXEC, jidStr, CRATE_PATH_IFCONFIG,
                       r.ifname, "up"},
                      "bring iface up in jail");

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
    default:
      return PrivOpsWirePure::parseValidateAndDispatch(v, body);
  }
  }();
  // 0.9.13: per-user audit tail (best-effort; no-op for uid=0 /
  // rootless off).
  maybeWritePerUserAudit(rootlessPerUser, operatorUid, v, result.status);
  return result;
}

} // namespace Crated
