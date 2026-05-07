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

// Validate a ZFS dataset name. Used by callers that build snapshot
// names from operator input. Allowed alphabet: [A-Za-z0-9_./:-];
// no leading slash, no `..` segments, length 1..255.
// Returns "" on success, error message otherwise.
std::string validateDatasetName(const std::string &ds);

} // namespace ZfsDatasetPure
