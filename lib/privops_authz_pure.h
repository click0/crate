// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Per-user authorization for privops verbs (authorize-before-dispatch).
//
// Background: the privops plane performs privileged operations on
// behalf of a connecting operator. Over the libnv socket the peer's
// uid is known (getpeereid), but historically the dispatcher ran the
// verb purely on its request arguments — the uid only fed the audit
// tail. A hostile operator in the privops group could therefore name
// another operator's ZFS dataset or RCTL umbrella. See
// docs/trust-model.md ("authorize before dispatch").
//
// This module gates the verbs that carry a *robust* ownership signal
// in the request itself, checked against the caller's per-user
// environment (PerUserEnvPure::composeForUid):
//
//   - attach_zfs / detach_zfs : the `dataset` must lie within the
//     caller's per-user ZFS prefix (<master>/<uid>).
//   - set_loginclass_rctl / clear_loginclass_rctl : the `loginclass`
//     must be the caller's own crate-<uid> umbrella.
//
// Every other verb returns Allow:
//   - host-global verbs (interface / pf / ipfw / nat / epair) cannot
//     be pool-scoped — they touch shared host state and stay host-wide
//     by design (gated only by privops-socket group membership);
//   - jid-scoped verbs (set_rctl, signal_jail, set_jail_cpuset, devfs,
//     query_jail_rctl, create/destroy_jail, mount_nullfs, ...) have no
//     request-carried owner today; enforcing them needs a jid->owner
//     registry, which is deferred. They remain host-wide for now.
//
// This is a pure, platform-independent decision function — the daemon
// (privops_handlers.cpp) resolves the caller's uid and env, calls
// authorize() before dispatch, and turns a non-Allow decision into a
// 403. Only invoked on the libnv path for a real uid > 0; the HTTP
// path (uid == 0, admin-only) is unaffected and stays host-wide.
//

#include <string>

#include "privops_pure.h"
#include "per_user_env_pure.h"

namespace PrivOpsAuthzPure {

enum class Decision {
  Allow,
  DenyForeignDataset,    // dataset outside the caller's per-user ZFS prefix
  DenyForeignLoginclass, // loginclass is not the caller's crate-<uid>
};

// True when `dataset` is the caller's prefix itself or a descendant
// ("<prefix>/..."). An empty `zfsPrefix` means per-user ZFS split is
// not configured, so there is no per-tenant dataset boundary to
// enforce — returns true (nothing to gate). The boundary check is
// slash-anchored so "<prefix>extra" does not match "<prefix>".
bool datasetOwned(const std::string &dataset, const std::string &zfsPrefix);

// Authorize a privops verb for the operator described by `env`
// (env = PerUserEnvPure::composeForUid(cfg, uid), uid > 0). `dataset`
// and `loginclass` are the corresponding request fields (empty when
// the verb doesn't carry them). Returns Allow for every verb that is
// not one of the gated, robustly-ownable verbs.
Decision authorize(PrivOpsPure::Verb v,
                   const std::string &dataset,
                   const std::string &loginclass,
                   const PerUserEnvPure::Env &env);

// Human-readable reason for a decision (used in the 403 body).
const char *decisionReason(Decision d);

} // namespace PrivOpsAuthzPure
