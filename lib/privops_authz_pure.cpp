// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_authz_pure.h"

namespace PrivOpsAuthzPure {

bool datasetOwned(const std::string &dataset, const std::string &zfsPrefix) {
  if (zfsPrefix.empty())
    return true;                 // no per-user ZFS split → nothing to gate
  if (dataset == zfsPrefix)
    return true;                 // the prefix root itself
  // Descendant: "<prefix>/...". Slash-anchored so "<prefix>extra"
  // does not pass as "<prefix>".
  return dataset.size() > zfsPrefix.size()
      && dataset.compare(0, zfsPrefix.size(), zfsPrefix) == 0
      && dataset[zfsPrefix.size()] == '/';
}

bool pathOwned(const std::string &path, const std::string &pathPrefix) {
  // Identical shape to datasetOwned — kept as a separate helper so each
  // call-site reads as "is this PATH inside the per-user path prefix"
  // rather than reusing the dataset spelling.
  if (pathPrefix.empty())  return true;
  if (path == pathPrefix)  return true;
  return path.size() > pathPrefix.size()
      && path.compare(0, pathPrefix.size(), pathPrefix) == 0
      && path[pathPrefix.size()] == '/';
}

OwnerLookup nullLookup() {
  OwnerLookup l;
  l.byJid  = [](unsigned)              { return Owner{}; };
  l.byName = [](const std::string &)   { return Owner{}; };
  l.byPath = [](const std::string &)   { return Owner{}; };
  return l;
}

namespace {

// Centralized jid/name ownership probe. Returns Allow if the lookup
// reports unknown (bootstrap concession) or matches env.uid; otherwise
// returns the appropriate deny code.
Decision checkOwnedJid(unsigned jid, const PerUserEnvPure::Env &env,
                       const OwnerLookup &lookup) {
  if (!lookup.byJid) return Decision::Allow;
  Owner o = lookup.byJid(jid);
  if (!o.known) return Decision::Allow;          // unknown jid -> bootstrap
  return o.uid == env.uid ? Decision::Allow : Decision::DenyForeignJid;
}

Decision checkOwnedName(const std::string &name,
                        const PerUserEnvPure::Env &env,
                        const OwnerLookup &lookup) {
  if (!lookup.byName) return Decision::Allow;
  Owner o = lookup.byName(name);
  if (!o.known) return Decision::Allow;
  return o.uid == env.uid ? Decision::Allow : Decision::DenyForeignJailName;
}

Decision checkOwnedPath(const std::string &path,
                        const PerUserEnvPure::Env &env,
                        const OwnerLookup &lookup) {
  if (!lookup.byPath) return Decision::Allow;
  Owner o = lookup.byPath(path);
  if (!o.known) return Decision::Allow;        // path not in any tracked jail
  return o.uid == env.uid ? Decision::Allow : Decision::DenyForeignPath;
}

} // namespace

Decision authorize(PrivOpsPure::Verb v,
                   const Request &req,
                   const PerUserEnvPure::Env &env,
                   const OwnerLookup &lookup) {
  using V = PrivOpsPure::Verb;
  switch (v) {
    case V::AttachZfs:
    case V::DetachZfs:
      return datasetOwned(req.dataset, env.zfsPrefix)
                 ? Decision::Allow
                 : Decision::DenyForeignDataset;

    case V::SetLoginclassRctl:
    case V::ClearLoginclassRctl:
      // env.loginclass is the caller's crate-<uid> umbrella (always
      // populated for uid > 0). An empty or foreign request loginclass
      // can't match, so it's denied — fail closed.
      return req.loginclass == env.loginclass
                 ? Decision::Allow
                 : Decision::DenyForeignLoginclass;

    // jid-scoped verbs gated against the registry (1.1.13).
    case V::SetRctl:
    case V::ClearRctl:
    case V::SetJailCpuset:
    case V::QueryJailRctl:
    case V::SignalJail:
      return checkOwnedJid(req.jid, env, lookup);

    // Name-scoped verb. The jail name itself is brand-new and there's
    // nothing in the registry to compare against on create; the gate
    // for create_jail is below (path-prefix). destroy_jail gates on
    // the name — it must be one this caller created.
    case V::DestroyJail:
      return checkOwnedName(req.jailName, env, lookup);

    // 1.1.15: create_jail's brand-new path must fall inside the
    // caller's per-user path prefix (cfg.pathMasterPrefix/<uid>). When
    // the deployment didn't configure pathMasterPrefix, env.pathPrefix
    // is empty and pathOwned() Allows — same opt-in shape as the ZFS
    // gate (cfg.zfsMasterPrefix). This is the last narrow item from
    // the 1.1.x trust-model open gap.
    case V::CreateJail:
      return pathOwned(req.path, env.pathPrefix)
                 ? Decision::Allow
                 : Decision::DenyForeignCreatePath;

    // 1.1.14: path-scoped verbs. The dispatcher fills req.path from
    // the right libnv field per verb:
    //   mount_nullfs / unmount_nullfs -> "target"  (must lie under
    //                                     an owned jail's path)
    //   apply_devfs_ruleset / add_devfs_unhide_rule -> "mount_path"
    //                                     (typically <jailPath>/dev)
    // An unknown path (no registry hit) is allowed — same bootstrap
    // concession as the jid/name gate (jails predating 1.1.13 aren't
    // in the registry).
    case V::MountNullfs:
    case V::UnmountNullfs:
    case V::ApplyDevfsRuleset:
    case V::AddDevfsUnhideRule:
      return checkOwnedPath(req.path, env, lookup);

    default:
      // Remaining host-global verbs (interface / pf / ipfw / nat /
      // epair) cannot be pool-scoped — they touch shared host state
      // and stay host-wide by design. create_jail's path argument
      // still needs validation against a per-user path prefix —
      // tracked as the next open item once Env grows pathPrefix.
      return Decision::Allow;
  }
}

Decision authorize(PrivOpsPure::Verb v,
                   const std::string &dataset,
                   const std::string &loginclass,
                   const PerUserEnvPure::Env &env) {
  Request r;
  r.dataset    = dataset;
  r.loginclass = loginclass;
  return authorize(v, r, env, nullLookup());
}

const char *decisionReason(Decision d) {
  switch (d) {
    case Decision::Allow:
      return "allow";
    case Decision::DenyForeignDataset:
      return "dataset is outside the caller's per-user ZFS prefix";
    case Decision::DenyForeignLoginclass:
      return "loginclass is not the caller's crate-<uid> umbrella";
    case Decision::DenyForeignJid:
      return "jid is owned by a different operator";
    case Decision::DenyForeignJailName:
      return "jail name is owned by a different operator";
    case Decision::DenyForeignPath:
      return "path lies inside a jail owned by a different operator";
    case Decision::DenyForeignCreatePath:
      return "create_jail path is outside the caller's per-user path prefix";
  }
  return "deny";
}

} // namespace PrivOpsAuthzPure
