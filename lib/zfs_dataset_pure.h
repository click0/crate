// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for ZFS-dataset name handling. Parser-only — anything
// that calls zfs(8) lives in lib/zfs_dataset.cpp.
//
// 0.8.25: extracted from lib/backup.cpp + lib/replicate.cpp where
// `findLatestBackupSuffix` and `datasetForJail` were duplicated
// near-verbatim. The pure parsing of `zfs list -H -t snapshot -o name`
// output is the testable bit.
//

#include <string>
#include <vector>

#include <cstdint>

namespace ZfsDatasetPure {

// Walk the multi-line output of `zfs list -H -t snapshot -o name -r
// <dataset>` and return the lexicographically-greatest backup-*
// suffix found. Returns "" if no backup-* snapshot is present.
//
// Convention: backup snapshots are named "<dataset>@backup-<utc-iso>"
// where <utc-iso> is lex-monotonic with time (see lib/backup_pure.cpp
// snapshotSuffix). So newest = lex-greatest.
//
// Tolerates trailing whitespace, CRLF, comment lines starting with '#',
// and lines that don't match the @backup-* shape (skipped silently).
std::string pickLatestBackupSuffix(const std::string &zfsListOutput);

// 1.1.69: the same walk pinned to ONE dataset and ONE prefix: only
// lines "<dataset>@<prefix>..." count, so a descendant's snapshot
// (tank/jails/web/data@backup-…) or another family (repl-…) cannot
// become the incremental base of this dataset's stream. `prefix` is
// e.g. "backup-" or "repl-"; returns the whole suffix ("backup-…") or "".
std::string pickLatestSuffix(const std::string &zfsListOutput,
                             const std::string &dataset,
                             const std::string &prefix);

// 1.1.69: the newest snapshot both sides hold — the only safe base of an
// incremental `zfs send -i` to a remote. `localOut` / `remoteOut` are
// `zfs list -H -t snapshot -o name -d 1` of the local and the remote
// dataset; a suffix counts when its prefix is one of `prefixes` and it
// appears in BOTH listings. "Newest" compares the text after the prefix
// (the UTC timestamp, lex-monotone), so a backup-… and a repl-… snapshot
// are ordered by time, not by prefix. Returns "" when nothing is common.
std::string pickLatestCommonSuffix(const std::string &localOut, const std::string &localDataset,
                                   const std::string &remoteOut, const std::string &remoteDataset,
                                   const std::vector<std::string> &prefixes);

// 1.1.69: every "<dataset>@<prefix>…" suffix in a listing, in listing
// order (what the two functions above consume; exposed for tests and
// for `replicate` to report what it saw).
std::vector<std::string> snapshotSuffixes(const std::string &zfsListOutput,
                                          const std::string &dataset,
                                          const std::string &prefix);

// Validate a ZFS dataset name. Used by callers that build snapshot
// names from operator input. Allowed alphabet: [A-Za-z0-9_./:-];
// no leading slash, no `..` segments, length 1..255.
// Returns "" on success, error message otherwise.
std::string validateDatasetName(const std::string &ds);

// --- Per-user dataset composition (0.9.9, rootless track) ---
//
// Single-tenant deployments stuff every jail under one shared
// prefix (`zroot/jails/<jail>`). For multi-tenant, alice and bob
// must not see each other's jail datasets — `zfs allow` gates
// per-prefix, so giving each operator their own subtree under
// the master prefix gets us the isolation.
//
// composePerUserPrefix("zroot/jails", 1000) -> "zroot/jails/1000"
// composePerUserDataset("zroot/jails", 1000, "web")
//   -> "zroot/jails/1000/web"
//
// Same uid-as-segment choice as runtime_paths_pure (0.9.8): uid
// is the stable key, not the username. Operators wanting
// username-shaped paths can do `zfs rename` after creation.
//
// `masterPrefix` is operator-supplied (`crated.conf
// zfs_master_prefix:`), so it goes through validateDatasetName
// before composition. `jailName` likewise validated upstream
// (PrivOpsPure::validateJailName). composeXxx assume both are
// already valid; the result is the deterministic concatenation.
//
// Returns a possibly-invalid dataset name if either input is
// invalid; callers should validate the result before passing
// to ZFS API. Tests cover the validate-result-also-valid case.

std::string composePerUserPrefix(const std::string &masterPrefix,
                                 uint32_t uid);

std::string composePerUserDataset(const std::string &masterPrefix,
                                  uint32_t uid,
                                  const std::string &jailName);

} // namespace ZfsDatasetPure
