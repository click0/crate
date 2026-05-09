// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Per-user RCTL accounting groups (0.9.11, rootless track).
//
// FreeBSD's rctl(8) gates resource limits per "subject": jail, user,
// loginclass, or process. Today crate sets per-jail RCTL rules
// (`jail:<jid>:<key>:deny=<value>`) — fine for single-tenant.
// For multi-tenant rootless, alice's jails should aggregate against
// alice's umbrella quota, not just per-jail.
//
// Loginclass is the natural unit:
//   - rctl can express `loginclass:crate-1000:memoryuse:deny=4G`
//   - login.conf assigns loginclass to UNIX accounts
//   - crated assigns each operator a loginclass on first contact
//
// This module composes:
//   - the per-user loginclass name (deterministic from uid)
//   - rctl(8) subject-tags for both jail-scoped and loginclass-
//     scoped rules, so the daemon can apply both layers at once
//
// Example flow:
//   alice (uid 1000) creates jail "web" → jid 7
//   crated applies:
//     jail:7:memoryuse:deny=2G              (per-jail, today)
//     loginclass:crate-1000:memoryuse:deny=4G  (umbrella, this PR)
//
// If alice creates a second jail with memoryuse=3G, the umbrella
// keeps her total at 4G (kernel enforces; new jail's own rule
// allows 3G but the loginclass cap fires first). Bob's loginclass
// crate-1001 has its own 4G — no cross-tenant interference.
//
// Pure module. No syscalls; no /etc/login.conf edits. The daemon-
// side wiring (creating loginclass entries via cap_mgmt(2) or
// pwd_mkdb, applying rules) lands in 0.9.12 alongside the migration
// doc.
//

#include <cstdint>
#include <string>
#include <vector>

namespace PerUserRctlPure {

// Compose a per-user loginclass name. Deterministic, alnum + dash
// only (login.conf restriction). Format:
//
//   loginclassName(0)    -> "crate-0"
//   loginclassName(1000) -> "crate-1000"
//   loginclassName(65534)-> "crate-65534"
//
// The "crate-" prefix scopes the namespace so operators with
// pre-existing custom loginclasses don't collide.
std::string loginclassName(uint32_t uid);

// Compose the rctl(8) subject tag for a jail-scoped rule.
//
//   jailSubject(7) -> "jail:7"
std::string jailSubject(int jid);

// Compose the rctl(8) subject tag for a loginclass-scoped rule.
//
//   loginclassSubject(1000) -> "loginclass:crate-1000"
std::string loginclassSubject(uint32_t uid);

// Build the full rctl(8) rule string. Subject + key + action +
// value. Action is fixed at "deny" today (matches what crate
// retune does); future rule types (log, sigterm) can extend.
//
//   buildRule("jail:7", "memoryuse", "2G")
//     -> "jail:7:memoryuse:deny=2G"
//
//   buildRule("loginclass:crate-1000", "memoryuse", "4G")
//     -> "loginclass:crate-1000:memoryuse:deny=4G"
std::string buildRule(const std::string &subject,
                      const std::string &key,
                      const std::string &rawValue);

// Compose the per-user umbrella rules from a {key -> value} list.
// Useful for the daemon to apply alice's whole quota set at jail-
// create time.
//
// `pairs` is a list of (key, rawValue). Both already validated
// upstream via RetunePure::validateRctlKey / validateRctlValue.
//
// Returns one rctl rule string per pair, all subject-tagged with
// the per-user loginclass.
struct KeyValue {
  std::string key;
  std::string rawValue;
};
std::vector<std::string> buildUserUmbrellaRules(uint32_t uid,
                                                const std::vector<KeyValue> &pairs);

// Validate a loginclass name as one our daemon would emit.
// Returns "" if `name` matches what `loginclassName(uid)` produces
// for some uid; otherwise an error. Used by the daemon to reject
// operator-supplied loginclass strings that don't fit the scheme
// (defence in depth — caller should never get to choose).
std::string validateLoginclassName(const std::string &name);

} // namespace PerUserRctlPure
