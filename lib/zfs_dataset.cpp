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

std::string findLatestBackupSuffix(const std::string &dataset) {
  try {
    auto raw = Util::execCommandGetOutput(
      {"/sbin/zfs", "list", "-H", "-t", "snapshot",
       "-o", "name", "-r", dataset},
      "list ZFS snapshots");
    return ZfsDatasetPure::pickLatestBackupSuffix(raw);
  } catch (...) {
    // No snapshots, or ZFS error — caller treats as "no prior",
    // matching the pre-0.8.25 backup.cpp / replicate.cpp behaviour.
    return "";
  }
}

} // namespace ZfsDataset
