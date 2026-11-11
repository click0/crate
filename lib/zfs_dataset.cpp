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
  const std::string what = errContext.empty() ? "operation" : errContext;
  // 1.1.72: by container name too (the kernel names the jail web_pid4242
  // or by its jid), as every other command since 1.1.70.
  unsigned matches = 0;
  auto j = JailQuery::findContainer(name, &matches);
  if (!j && matches > 1)
    ERR("'" << name << "' matches " << matches << " running jails — name one by its jid or kernel name")
  if (!j)
    ERR("jail '" << name << "' not found or not running (" << what << " requires a running jail)")
  if (!Util::Fs::isOnZfs(j->path))
    ERR("jail '" << name << "' is not on ZFS — " << what << " requires ZFS")
  // 1.1.72: the jail's OWN dataset. statfs of a plain jail directory
  // names the dataset that contains it — on a default install the
  // host's root — and backup / replicate sent the whole host.
  auto ds = Util::Fs::getZfsDatasetMountedAt(j->path);
  if (ds.empty())
    ERR("jail '" << name << "' has no ZFS dataset of its own: " << j->path << " is a directory in "
        << Util::Fs::getZfsDataset(j->path) << ", and " << what << " would take all of that (a "
        "--warm-base run has its own clone; a plain `crate run` does not get a dataset yet)")
  return ds;
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
