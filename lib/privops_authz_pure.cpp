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

Decision authorize(PrivOpsPure::Verb v,
                   const std::string &dataset,
                   const std::string &loginclass,
                   const PerUserEnvPure::Env &env) {
  using V = PrivOpsPure::Verb;
  switch (v) {
    case V::AttachZfs:
    case V::DetachZfs:
      return datasetOwned(dataset, env.zfsPrefix)
                 ? Decision::Allow
                 : Decision::DenyForeignDataset;

    case V::SetLoginclassRctl:
    case V::ClearLoginclassRctl:
      // env.loginclass is the caller's crate-<uid> umbrella (always
      // populated for uid > 0). An empty or foreign request loginclass
      // can't match, so it's denied — fail closed.
      return loginclass == env.loginclass
                 ? Decision::Allow
                 : Decision::DenyForeignLoginclass;

    default:
      // Host-global and jid-scoped verbs: not gated here (see header).
      return Decision::Allow;
  }
}

const char *decisionReason(Decision d) {
  switch (d) {
    case Decision::Allow:
      return "allow";
    case Decision::DenyForeignDataset:
      return "dataset is outside the caller's per-user ZFS prefix";
    case Decision::DenyForeignLoginclass:
      return "loginclass is not the caller's crate-<uid> umbrella";
  }
  return "deny";
}

} // namespace PrivOpsAuthzPure
