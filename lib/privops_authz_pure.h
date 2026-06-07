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
// 1.1.13 extension — jid-scoped verbs. The privops daemon now keeps a
// jid->owner registry (lib/jid_owner_registry.{h,cpp}), populated at
// create_jail time. authorize() takes a small lookup interface to that
// registry and gates the verbs that carry a jid or jail name in the
// request: SignalJail, SetRctl, ClearRctl, SetJailCpuset,
// QueryJailRctl, DestroyJail. An unknown jid/name is allowed (jails
// pre-dating 1.1.13 aren't in the registry); a *known* jid/name with
// the wrong owner is denied 403. Path-scoped verbs (devfs, mount) and
// create_jail path validation remain in the open gap.
//

#include <functional>
#include <string>

#include "privops_pure.h"
#include "per_user_env_pure.h"

namespace PrivOpsAuthzPure {

enum class Decision {
  Allow,
  DenyForeignDataset,    // dataset outside the caller's per-user ZFS prefix
  DenyForeignLoginclass, // loginclass is not the caller's crate-<uid>
  DenyForeignJid,        // jid is in the registry and owned by another uid
  DenyForeignJailName,   // jail name is in the registry and owned by another uid
};

// Result of looking a target up in the daemon's jid->owner registry.
struct Owner {
  bool     known = false;   // false => not in registry (pre-1.1.13 / external jail)
  uint32_t uid   = 0;       // operator uid recorded at create_jail (only valid if known)
};

// Lookup callbacks injected by the daemon. The pure module never
// reads state — it only queries through these. Either may be null:
// authorize falls back to "unknown" (Allow) and the daemon's audit
// tail still records the call.
struct OwnerLookup {
  std::function<Owner(unsigned jid)>             byJid;
  std::function<Owner(const std::string &name)>  byName;
};

// Convenience: a lookup where every probe reports "unknown". Useful
// for the existing dataset/loginclass-only tests and for the HTTP
// admin path (uid==0, gate is skipped anyway).
OwnerLookup nullLookup();

// All of the per-verb request fields the authorizer might consult.
// Daemon fills only the ones the request actually carries; unused
// fields stay default-initialized.
struct Request {
  std::string dataset;
  std::string loginclass;
  std::string jailName;
  unsigned    jid = 0;
};

// True when `dataset` is the caller's prefix itself or a descendant
// ("<prefix>/..."). An empty `zfsPrefix` means per-user ZFS split is
// not configured, so there is no per-tenant dataset boundary to
// enforce — returns true (nothing to gate). The boundary check is
// slash-anchored so "<prefix>extra" does not match "<prefix>".
bool datasetOwned(const std::string &dataset, const std::string &zfsPrefix);

// Authorize a privops verb for the operator described by `env`
// (env = PerUserEnvPure::composeForUid(cfg, uid), uid > 0).
//
// Returns Allow for every verb that is NOT one of the gated classes:
// dataset (attach_zfs/detach_zfs), loginclass (set_loginclass_rctl /
// clear_loginclass_rctl), or jid/name-scoped (set_rctl, clear_rctl,
// set_jail_cpuset, query_jail_rctl, signal_jail, destroy_jail).
//
// For the jid/name-scoped verbs: an unknown target (lookup returns
// known=false) is allowed — the registry does not know about jails
// created before 1.1.13. A known target with the wrong owner is
// denied 403 with DenyForeignJid / DenyForeignJailName.
Decision authorize(PrivOpsPure::Verb v,
                   const Request &req,
                   const PerUserEnvPure::Env &env,
                   const OwnerLookup &lookup);

// Backward-compatible thin wrapper for the dataset/loginclass-only
// tests written for 1.1.12. Equivalent to authorize() with all other
// Request fields empty and nullLookup().
Decision authorize(PrivOpsPure::Verb v,
                   const std::string &dataset,
                   const std::string &loginclass,
                   const PerUserEnvPure::Env &env);

// Human-readable reason for a decision (used in the 403 body).
const char *decisionReason(Decision d);

} // namespace PrivOpsAuthzPure
