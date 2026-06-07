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

OwnerLookup nullLookup() {
  OwnerLookup l;
  l.byJid  = [](unsigned)              { return Owner{}; };
  l.byName = [](const std::string &)   { return Owner{}; };
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

    // Name-scoped verbs. CreateJail itself is intentionally NOT gated
    // here (the name is brand-new — there's nothing to compare to yet;
    // path validation is the open follow-up). DestroyJail IS gated:
    // the name already exists and must be one this caller created.
    case V::DestroyJail:
      return checkOwnedName(req.jailName, env, lookup);

    default:
      // Host-global verbs (interface / pf / ipfw / nat / epair) cannot
      // be pool-scoped — they touch shared host state. The remaining
      // path-scoped verbs (devfs apply/unhide, mount/unmount nullfs)
      // still need design work and stay host-wide for now.
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
  }
  return "deny";
}

} // namespace PrivOpsAuthzPure
