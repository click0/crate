// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for `crate backup` / `crate restore`.
//
// Strategy:
//   - Snapshot-based: take a fresh ZFS snapshot of the jail's
//     dataset, emit `zfs send` stream into a file. ZFS deduplicates
//     and compresses internally — there's no need for an extra
//     gzip/xz wrapper.
//   - Incremental: when --since <prev-snap> is given, the runtime
//     emits `zfs send -i prev curr`, producing a delta-only stream.
//     Restore requires the chain of streams since the last full.
//
// This module owns:
//   - filename + snapshot-name conventions
//   - argv builders for `zfs snapshot`, `zfs send`, `zfs recv`,
//     `zfs destroy`
//   - the decision: full-vs-incremental based on inputs
//   - retention policy parser (`daily=7,weekly=4`) for cron-style
//     pruning by `crate backup --prune`
//
// All file I/O lives in lib/backup.cpp.
//

#include <cstdint>
#include <string>
#include <vector>

namespace BackupPure {

// --- Naming ---

// Build a snapshot name suffix from a UNIX timestamp:
//   1730000000 → "backup-2024-10-27T03:33:20Z"
// We standardise on UTC and zero-pad so lexicographic order ==
// chronological order (cron-friendly).
std::string snapshotSuffix(long unixEpoch);

// Build the full snapshot identifier:
//   pool/jails/foo, "backup-2024-10-27T03:33:20Z" -> pool/jails/foo@<that>
std::string fullSnapshotName(const std::string &dataset,
                             const std::string &suffix);

// Build the output filename for the stream. Format:
//   <jailName>-<suffix>[.inc-from-<prevSuffix>].zstream
// The .inc-from-* tag distinguishes incremental from full streams
// at glance — operators don't need to keep separate index files.
std::string streamFilename(const std::string &jailName,
                           const std::string &suffix,
                           const std::string &incFromSuffix);

// --- Validators ---

// Container/jail name as seen by `crate backup <name>`. Same rules
// as the daemon's TransferPure::validateArtifactName modulo the
// length cap (we allow up to 64 chars here — same as
// MigratePure::validateContainerName).
std::string validateJailName(const std::string &name);

// Output directory must be absolute, no shell metacharacters, no
// `..` segments. Same shape as wireguard_runtime_pure's path
// validator but with a more permissive 1024-char cap (backup dirs
// are operator-chosen on big disks).
std::string validateOutputDir(const std::string &dir);

// Validate a snapshot name supplied via --since. Must NOT contain
// `@` (we tack it on ourselves) or `/`. ASCII alnum + `._-:T+` to
// allow ISO-8601-ish timestamps.
std::string validateSinceName(const std::string &name);

// --- Argv builders ---

// `zfs snapshot <dataset>@<suffix>`
std::vector<std::string> buildSnapshotArgv(const std::string &dataset,
                                           const std::string &suffix);

// `zfs send <full-snap-name>`            (no --since)
// `zfs send -i <prev-snap> <curr-snap>`  (with --since)
//
// `prevSuffix` empty → full stream; otherwise incremental.
std::vector<std::string> buildSendArgv(const std::string &dataset,
                                       const std::string &currSuffix,
                                       const std::string &prevSuffix);

// `zfs recv <dest-dataset>` — used by `crate restore`.
std::vector<std::string> buildRecvArgv(const std::string &destDataset);

// `zfs destroy <dataset>@<suffix>` — used by --prune to retire
// snapshots beyond the retention window.
std::vector<std::string> buildDestroySnapshotArgv(const std::string &dataset,
                                                  const std::string &suffix);

// --- Retention ---

struct RetentionPolicy {
  unsigned hourly  = 0;
  unsigned daily   = 0;
  unsigned weekly  = 0;
  unsigned monthly = 0;
};

// Parse a comma-separated retention string:
//   "hourly=24,daily=7,weekly=4,monthly=12"
// Unknown keys / non-numeric values produce an error. Returns "" on
// success and fills `out`.
std::string parseRetention(const std::string &spec, RetentionPolicy &out);

// --- Plan ---

// Decide what shape the run will take, given inputs.
struct Plan {
  enum class Kind { Full, Incremental, Error };
  Kind kind = Kind::Full;
  std::string reason;        // populated when kind == Error
  std::string sinceSuffix;   // empty for Full; the prev snapshot for Incremental
};

struct Inputs {
  // True if `--since <name>` was given on the command line.
  bool sinceProvided = false;
  std::string sinceName;
  // True if the last `zfs list` showed at least one snapshot
  // matching our backup-* prefix on this dataset (caller decides
  // by talking to ZFS).
  bool priorBackupExists = false;
  std::string priorSnapshotSuffix; // most-recent backup-* suffix, if any
};

// Pure decision: build the plan. Rules:
//   - sinceProvided=true              → Incremental from sinceName
//   - sinceProvided=false, priorBackupExists=true, --auto-incremental
//                                     → Incremental from priorSnapshotSuffix
//   - otherwise                        → Full
// `autoIncremental` is the runtime flag.
Plan choosePlan(const Inputs &in, bool autoIncremental);

} // namespace BackupPure
