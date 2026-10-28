// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "zfs_dataset.h"
#include "zfs_dataset_pure.h"
#include "jail_query.h"
#include "util.h"
#include "err.h"

#define ERR(msg...) ERR2("zfs-dataset", msg)

namespace ZfsDataset {

std::string datasetForJail(const std::string &name,
                           const std::string &errContext) {
  auto j = JailQuery::getJailByName(name);
  if (!j)
    ERR("jail '" << name << "' not found or not running ("
        << (errContext.empty() ? "operation" : errContext)
        << " requires a running jail)")
  if (!Util::Fs::isOnZfs(j->path))
    ERR("jail '" << name << "' is not on ZFS — "
        << (errContext.empty() ? "operation" : errContext)
        << " requires ZFS")
  return Util::Fs::getZfsDataset(j->path);
}

std::vector<std::string> listSnapshotsArgv(const std::string &dataset) {
  // 1.1.69: `-d 1` — this dataset's own snapshots only. `-r` listed the
  // descendants too (tank/jails/web/data@backup-…) and the parser did
  // not pin the dataset, so a child's snapshot could be picked as the
  // incremental base of the parent's stream.
  return {"/sbin/zfs", "list", "-H", "-t", "snapshot", "-o", "name", "-d", "1", dataset};
}

std::string listSnapshots(const std::string &dataset) {
  try {
    return Util::execCommandGetOutput(listSnapshotsArgv(dataset), "list ZFS snapshots");
  } catch (...) {
    // No snapshots, or ZFS error — callers treat as "no prior",
    // matching the pre-0.8.25 backup.cpp / replicate.cpp behaviour.
    return "";
  }
}

std::string findLatestBackupSuffix(const std::string &dataset) {
  return ZfsDatasetPure::pickLatestSuffix(listSnapshots(dataset), dataset, "backup-");
}

} // namespace ZfsDataset
