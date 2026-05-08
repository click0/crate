// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Per-user runtime path layout (0.9.8, rootless track foundation).
//
// Today every operator shares `/var/run/crate/`: leases, exports,
// imports, audit log, control sockets all live under one tree.
// In a single-tenant homelab that's fine. For multi-tenant
// deployments — the rootless track's primary use case — alice
// shouldn't see bob's container leases or be able to clobber his
// export staging file.
//
// This release introduces the path scheme without wiring any
// existing call sites to it. That keeps the existing setuid-prod
// flow byte-identical while giving subsequent 0.9.x releases a
// stable contract to migrate one subsystem at a time:
//
//   /var/run/crate/                — legacy single-tenant root
//   /var/run/crate/<uid>/          — per-user root (this release)
//   /var/run/crate/<uid>/leases/   — IP leases (0.9.10 will move them)
//   /var/run/crate/<uid>/exports/  — export staging (0.9.12)
//   /var/run/crate/<uid>/imports/  — import staging (0.9.12)
//   /var/run/crate/<uid>/audit.log — per-user audit tail
//
// The main control socket (`/var/run/crate/crated.sock`) and the
// per-operator control sockets (`/var/run/crate/control/<name>.sock`)
// stay where they are. The daemon listens once, fans out to per-user
// directories based on the requesting operator's resolved uid.
//
// Design choices documented for tests:
//   - uid 0 (root) maps to `/var/run/crate/0/`, NOT to the legacy
//     `/var/run/crate/`. The legacy tree is a pre-0.9.x compat
//     surface; root using rootless mode gets its own subtree just
//     like any other operator. The `legacyRoot()` helper exists
//     for explicit fallback.
//   - The `<uid>` segment is a decimal integer with no padding.
//     We don't try to look up the uid's username (operators may
//     deploy with NIS / LDAP and the uid->name map could change
//     across crated reloads; uid is the stable key).
//   - Path validators forbid traversal — uid is bounded to
//     0..2^31-1 (signed-int range) to match POSIX uid_t practice.
//

#include <cstdint>
#include <string>

namespace RuntimePathsPure {

// Returns "/var/run/crate" (no trailing slash). Single-tenant
// legacy root; existing call sites keep using this until they
// migrate to per-user.
std::string legacyRoot();

// Returns "/var/run/crate/<uid>" (no trailing slash). The bare
// per-user root, used as a parent for leases / exports / imports.
// Caller is responsible for mkdir -p with appropriate mode
// (typically 0700 root:<user-group>).
std::string perUserRoot(uint32_t uid);

// "/var/run/crate/<uid>/leases" — directory holding per-jail
// IP lease files. Today these all sit in
// /var/run/crate/network-leases.txt (single file); the migration
// in 0.9.10 splits into per-user dirs.
std::string perUserLeasesDir(uint32_t uid);

// "/var/run/crate/<uid>/leases/<jailName>.lease" — single lease
// file. Caller has already validated jailName via
// PrivOpsPure::validateJailName.
std::string perUserLeaseFile(uint32_t uid, const std::string &jailName);

// "/var/run/crate/<uid>/exports" — export staging directory
// (operator-bounded scratch space for crate export → download).
std::string perUserExportsDir(uint32_t uid);

// "/var/run/crate/<uid>/imports" — import staging directory.
std::string perUserImportsDir(uint32_t uid);

// "/var/run/crate/<uid>/audit.log" — per-user audit log tail.
// The system audit (cap_syslog dual-write) keeps logging the
// canonical record; this is the operator-readable copy.
std::string perUserAuditLog(uint32_t uid);

// --- Validators ---

// Ensure a uid is in the safe range we encode into paths
// (0 .. INT32_MAX). Returns "" on success, otherwise a one-line
// reason. Larger uids are theoretically possible on 64-bit
// systems but we never expect them — bounding here catches
// integer-handling bugs upstream.
std::string validateUid(int64_t uid);

} // namespace RuntimePathsPure
