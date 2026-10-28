// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Runtime helpers around ZFS datasets — the bits that call zfs(8) /
// JailQuery. Pure parsing lives in lib/zfs_dataset_pure.h.
//
// 0.8.25: extracted from lib/backup.cpp + lib/replicate.cpp dedup.
// daemon/routes.cpp keeps its own datasetForJail because that one
// has different semantics (jail-not-found falls through to "treat
// the input as a dataset name" instead of throwing).
//

#include <string>
#include <vector>

namespace ZfsDataset {

// Resolve a jail name to its ZFS dataset.
// Throws (via ERR) if:
//   - the jail isn't running
//   - the jail's path isn't on ZFS
// errContext appears in the error message ("backup" / "replicate" /
// ...) so operators see which command surfaced the failure.
std::string datasetForJail(const std::string &name,
                           const std::string &errContext);

// Run `zfs list -H -t snapshot -o name -d 1 <dataset>` and return
// the lex-greatest backup-* suffix of THAT dataset (1.1.69: not of
// its descendants, not of the repl-* family). Returns "" if no
// backup snapshot exists or zfs list fails (caller treats that as
// "no prior", same as pre-0.8.25 behaviour).
std::string findLatestBackupSuffix(const std::string &dataset);

// 1.1.69: the raw `zfs list -H -t snapshot -o name -d 1 <dataset>`
// output ("" on failure) and the argv that produces it — `replicate`
// runs the same command on the remote over ssh.
std::string listSnapshots(const std::string &dataset);
std::vector<std::string> listSnapshotsArgv(const std::string &dataset);

} // namespace ZfsDataset
