// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for `crate template warm` — capture the on-disk
// state of a running jail as a ZFS clone the operator can later
// pass to `crate run --warm-base <dataset>` to skip cold-create
// work (pkg install, profile init, asset cache priming).
//
// What this gives us — and what it doesn't:
//
//   YES  — pkg install, /var/db caches, fontconfig, db migrations,
//          npm install output, anything written to disk before the
//          warm point is captured. Subsequent `crate run` clones
//          the dataset (instant, ZFS) and starts in 1-2 sec
//          instead of 30+ sec.
//   NO   — process memory, open file descriptors, unflushed page
//          cache, browser tabs, X11 sessions. That's the
//          Firecracker-style snapshot we documented as
//          out-of-scope for jail-based architectures (no CRIU on
//          FreeBSD; bhyve VMs are a separate product).
//
// The runtime side (lib/warm.cpp) is a thin shell around `zfs
// snapshot` + `zfs clone`. Everything in this module is
// validation + argv building, no I/O.
//

#include <string>
#include <vector>

namespace WarmPure {

// --- Validators ---

// Validate the destination ZFS dataset for the warm template
// (`tank/templates/firefox-warm`). Same alphabet rules as
// ReplicatePure::validateDestDataset (alnum + `._-/`, no `//`,
// no `.`/`..`, no leading/trailing slash) — a warm template
// lives in the local pool, not on a remote host, but the
// shell-injection surface is identical.
std::string validateTemplateDataset(const std::string &ds);

// Validate the snapshot-suffix component of a warm name. Allowed:
// alnum + `._-:T+` (ISO-8601-friendly). 1..64 chars.
std::string validateSnapshotSuffix(const std::string &suffix);

// --- Naming ---

// Build the snapshot suffix used as the warm-point marker:
//   warm-2026-05-04T12:00:00Z
// Lex-sortable so retention pruning is `ls -1 | sort | head -n -N`,
// the same convention as `crate backup` (0.7.0).
std::string warmSnapshotSuffix(long unixEpoch);

// Build the full snapshot identifier "<dataset>@<suffix>".
std::string fullSnapshotName(const std::string &dataset,
                             const std::string &suffix);

// --- Argv builders ---

// `zfs snapshot <sourceDataset>@<suffix>`
std::vector<std::string> buildSnapshotArgv(const std::string &sourceDataset,
                                           const std::string &suffix);

// `zfs clone <sourceDataset>@<suffix> <templateDataset>`
//
// The clone is a copy-on-write child of the source snapshot. It
// occupies near-zero space until the operator (or `crate run`)
// writes new data into it. This is the property that makes
// "instant warm-up" cheap.
std::vector<std::string> buildCloneArgv(const std::string &sourceDataset,
                                        const std::string &suffix,
                                        const std::string &templateDataset);

// `zfs promote <templateDataset>` — optional follow-up that
// flips the parent/child relationship so the template is no
// longer a clone of a specific snapshot. Operators run this
// when they want to be free to delete old snapshots without
// breaking the template. We expose the helper but don't run it
// by default — promotion changes accounting and some operators
// prefer the clone graph as-is.
std::vector<std::string> buildPromoteArgv(const std::string &templateDataset);

// --- Warm-base consumer side (0.7.9) ---
//
// `crate run --warm-base <dataset> --name <name>` boots a fresh jail
// from a warm template's ZFS clone instead of extracting a .crate
// archive. The runtime side:
//   1. zfs snapshot <warmDataset>@warmrun-<utc>      (fresh marker)
//   2. zfs clone <warmDataset>@warmrun-<utc> <parent>/jail-<name>-<hex>
//   3. ZFS auto-mounts the clone at jailPath via mountpoint inheritance
//   4. RunAtEnd: zfs destroy <clone> + zfs destroy <snap>
//
// This module owns the naming + validators; the snapshot/clone/destroy
// argv builders above (and ZfsOps) handle the actual ZFS calls.

// Validate a jail name supplied via `crate run --name <name>`. Same
// rules as ReplicatePure::validateContainerName / BackupPure::
// validateJailName (alnum + ._- 1..64 chars). Used only with
// --warm-base where there's no .crate file to derive the name from.
std::string validateJailName(const std::string &name);

// Suffix for the run-time snapshot we take of the warm template
// before cloning it. Distinct prefix ("warmrun-") from the warm
// template's own snapshot ("warm-") so `zfs list` operators can
// tell them apart and prune them with different retention rules.
//   warmrun-2026-05-04T12:00:00Z
std::string warmRunSnapshotSuffix(long unixEpoch);

// Build the destination clone's full dataset name. The clone lives
// alongside other jails so its mountpoint inherits to jailPath
// without an explicit `zfs set mountpoint=...`.
//   parent="tank/jails", name="firefox", hex="abcd"
//   -> "tank/jails/jail-firefox-abcd"
//
// `parentDataset` is the ZFS dataset that owns the jail directory
// (e.g. Util::Fs::getZfsDataset(Locations::jailDirectoryPath)).
// `hex` is whatever the runtime feeds in (typically Util::randomHex(4)).
std::string warmRunCloneName(const std::string &parentDataset,
                             const std::string &jailName,
                             const std::string &hex);

} // namespace WarmPure
