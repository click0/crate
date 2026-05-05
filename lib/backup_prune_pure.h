// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for `crate backup-prune`.
//
// Companion to lib/backup_pure.h. The backup module produces files
// named  <jail>-backup-<utc-iso8601>.zstream  (full streams) and
//        <jail>-backup-<curr>.inc-from-<prev>.zstream  (incremental).
// Operators accumulate these on a backup volume; this module decides
// which ones to keep under a Proxmox-style retention policy and
// which to delete.
//
// Bucketing rule (matches Proxmox vzdump-prune semantics):
//   - For each retention bucket type with N>0 (hourly|daily|weekly|
//     monthly), walk full streams newest -> oldest. The newest
//     full stream that lands in a fresh bucket key is kept; later
//     fulls in the same bucket are dropped. Stop when N distinct
//     buckets are seen.
//   - The kept set is the UNION across bucket types. Same file kept
//     by multiple types still counts as one.
//   - Incrementals are kept iff their base full is kept. Otherwise
//     they're orphans (operator-controllable: keep with warning, or
//     delete via --delete-orphans).
//
// All file I/O lives in lib/backup_prune.cpp.
//
// Why files (and not source-side ZFS snapshots)? Backup directories
// live on a separate volume (NFS, USB disk, S3-mounted FS) and grow
// independently of the source pool's snapshot retention. Operators
// often keep source snapshots short-lived but want stream files for
// years. `crate backup-prune` operates on the dir; `zfs destroy`
// of source snapshots stays operator-driven.
//

#include "backup_pure.h"

#include <cstdint>
#include <string>
#include <vector>

namespace BackupPrunePure {

// One parsed backup-stream filename. Both fulls and incrementals live
// in the same struct; `incFromSuffix` distinguishes them.
struct StreamFile {
  std::string filename;        // basename only, e.g. "myjail-backup-...-...Z.zstream"
  std::string jailName;        // parsed from prefix
  std::string suffix;          // "backup-2026-01-01T00:00:00Z" — the curr snapshot
  std::string incFromSuffix;   // empty for full streams; "backup-..." for incrementals
  long unixEpoch = 0;          // parsed from suffix; 0 if parse failed
};

// Validate the prune target directory. Same rules as
// BackupPure::validateOutputDir (absolute, no shell metas, no '..').
std::string validateDir(const std::string &dir);

// Optional --jail filter. Same rules as BackupPure::validateJailName.
// Empty input -> "" (means "no filter, consider all jails in dir").
std::string validateJailFilter(const std::string &name);

// Parse one filename. Schema:
//   <jail>-backup-YYYY-MM-DDTHH:MM:SSZ.zstream
//   <jail>-backup-YYYY-MM-DDTHH:MM:SSZ.inc-from-backup-YYYY-...Z.zstream
//
// Returns true on success and fills `out`. Returns false on parse
// failure with `errOut` populated. Filenames not matching the
// schema (other apps writing to the dir) are skipped silently by
// the caller — they MUST not be flagged as errors.
bool parseStreamFilename(const std::string &basename,
                         StreamFile &out,
                         std::string &errOut);

// Parse the timestamp portion of a "backup-YYYY-MM-DDTHH:MM:SSZ"
// suffix into a UNIX epoch (UTC). Returns 0 on parse failure
// (the only invalid epoch we care about — 1970-01-01T00:00:00Z is
// not a date anyone would name a backup).
long parseSuffixEpoch(const std::string &suffix);

// Bucket key derivations. Returned values are opaque integers; only
// equality matters. UTC throughout.
//   hour   key: epoch / 3600
//   day    key: epoch / 86400
//   week   key: epoch / (86400 * 7)
//   month  key: gmtime -> year*12 + month  (calendar-aligned)
long hourBucket(long epoch);
long dayBucket(long epoch);
long weekBucket(long epoch);
long monthBucket(long epoch);

// Decision result.
struct PruneDecision {
  std::vector<std::string> keep;     // basenames to retain
  std::vector<std::string> remove;   // basenames to delete
  std::vector<std::string> orphans;  // incrementals whose base would be removed
};

// Decide what to keep / remove. `policy` is the parsed retention
// (BackupPure::RetentionPolicy). `deleteOrphans` controls whether
// orphaned incrementals go into `remove` (true) or `orphans` (false).
//
// Files with epoch == 0 (unparseable timestamp) are treated as orphans:
// they're never automatically removed without --delete-orphans.
//
// Returns the decision; never throws. The basenames in keep/remove/
// orphans are taken from `files[i].filename` and the three lists are
// disjoint.
PruneDecision decidePrune(const std::vector<StreamFile> &files,
                          const BackupPure::RetentionPolicy &policy,
                          bool deleteOrphans);

// Convenience: the full set of bucketing keepers as
// (file-index -> reason) pairs, exposed for tests / verbose output.
struct KeepReason {
  size_t      fileIndex = 0;
  std::string reason;          // "hourly:N" / "daily:N" / "weekly:N" / "monthly:N"
};

std::vector<KeepReason> explainKeeps(const std::vector<StreamFile> &files,
                                     const BackupPure::RetentionPolicy &policy);

} // namespace BackupPrunePure
