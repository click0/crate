// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// `crate replicate <jail> --to <ssh-remote>` — ZFS storage
// replication via `zfs send | ssh ... 'zfs recv'`. Reuses
// lib/backup_pure.cpp for snapshot naming + plan choice; SSH
// argv building lives in lib/replicate_pure.cpp.
//

#include "args.h"
#include "backup_pure.h"
#include "commands.h"
#include "jail_query.h"
#include "replicate_pure.h"
#include "util.h"
#include "zfs_dataset.h"
#include "zfs_dataset_pure.h"   // 1.1.69: the common-base pick
#include "err.h"

#include <rang.hpp>

#include <ctime>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>

#define ERR(msg...) ERR2("replicate", msg)

// 0.8.25: datasetForJail + findLatestBackupSuffix moved to
// lib/zfs_dataset.{h,cpp} where they're shared with backup.cpp.

bool replicateCrate(const Args &args) {
  // Validate inputs (everything is shell-bound — paranoia-level
  // checks live in replicate_pure).
  if (auto e = BackupPure::validateJailName(args.replicateTarget); !e.empty())
    ERR(e)
  if (auto e = ReplicatePure::validateSshRemote(args.replicateTo); !e.empty())
    ERR("--to: " << e)
  if (auto e = ReplicatePure::validateDestDataset(args.replicateDestDataset);
      !e.empty())
    ERR("--dest-dataset: " << e)
  if (!args.replicateSshKey.empty())
    if (auto e = ReplicatePure::validateSshKey(args.replicateSshKey); !e.empty())
      ERR("--ssh-key: " << e)
  if (!args.replicateSshConfig.empty())
    if (auto e = ReplicatePure::validateSshKey(args.replicateSshConfig); !e.empty())
      ERR("--ssh-config: " << e)
  for (auto &o : args.replicateSshOpts)
    if (auto e = ReplicatePure::validateSshOpt(o); !e.empty())
      ERR("--ssh-opt '" << o << "': " << e)
  if (!args.replicateSince.empty())
    if (auto e = BackupPure::validateSinceName(args.replicateSince); !e.empty())
      ERR("--since: " << e)

  ReplicatePure::ReplicateRequest req;
  req.sourceDataset = ZfsDataset::datasetForJail(args.replicateTarget, "replicate");
  req.destDataset   = args.replicateDestDataset;

  // SSH transport spec.
  if (auto e = ReplicatePure::parseSshRemote(args.replicateTo, req.ssh);
      !e.empty())
    ERR("--to: " << e)
  req.ssh.port         = args.replicateSshPort;
  req.ssh.identityFile = args.replicateSshKey;
  req.ssh.configFile   = args.replicateSshConfig;
  req.ssh.extraOpts    = args.replicateSshOpts;

  // Plan: full vs. incremental. 1.1.69: the base of an incremental must
  // exist on BOTH sides. Until now --auto-incremental took the newest
  // local backup-* snapshot — which `crate backup` also makes, so a file
  // backup between two replications became the base of the next `zfs
  // send -i` and the remote answered "incremental source does not
  // match". Now: list this dataset's snapshots here and on the remote
  // and take the newest the two listings share (repl-* — our own family
  // since 1.1.69 — or a backup-* an older replicate created). Nothing in
  // common (first run, remote dataset missing, remote pruned) → full.
  BackupPure::Inputs in;
  in.sinceProvided = !args.replicateSince.empty();
  in.sinceName     = args.replicateSince;
  if (!in.sinceProvided && args.replicateAutoIncremental) {
    auto localOut = ZfsDataset::listSnapshots(req.sourceDataset);
    std::string remoteOut;
    try {
      remoteOut = Util::execCommandGetOutput(
        ReplicatePure::buildSshArgv(req.ssh,
                                    ReplicatePure::buildRemoteListSnapshotsCommand(req.destDataset)),
        "list the remote dataset's snapshots over ssh");
    } catch (...) {
      remoteOut.clear();   // dataset absent on the remote (or ssh failed): no common base
    }
    auto common = ZfsDatasetPure::pickLatestCommonSuffix(
      localOut, req.sourceDataset, remoteOut, req.destDataset,
      {BackupPure::kReplPrefix, BackupPure::kBackupPrefix});
    if (!common.empty()) {
      in.priorBackupExists   = true;
      in.priorSnapshotSuffix = common;
    } else if (!ZfsDatasetPure::snapshotSuffixes(localOut, req.sourceDataset, BackupPure::kReplPrefix).empty()
               || !ZfsDatasetPure::snapshotSuffixes(localOut, req.sourceDataset, BackupPure::kBackupPrefix).empty()) {
      std::cerr << rang::fg::yellow << "replicate: no snapshot is present on both sides — "
                << "sending a full stream (the remote dataset must not exist yet, or pass --since)"
                << rang::style::reset << std::endl;
    }
  }
  auto plan = BackupPure::choosePlan(in, args.replicateAutoIncremental);
  if (plan.kind == BackupPure::Plan::Kind::Error)
    ERR(plan.reason)

  req.currSnapshotSuffix = BackupPure::snapshotSuffixWithPrefix(BackupPure::kReplPrefix, ::time(nullptr));
  req.prevSnapshotSuffix =
    (plan.kind == BackupPure::Plan::Kind::Incremental) ? plan.sinceSuffix : "";

  // Take the snapshot locally.
  Util::execCommand(BackupPure::buildSnapshotArgv(req.sourceDataset,
                                                  req.currSnapshotSuffix),
                    "zfs snapshot");

  // Stream `zfs send ... | ssh remote 'zfs recv ...'`.
  std::cerr << rang::fg::cyan << "replicate: "
            << (req.prevSnapshotSuffix.empty() ? "full" : "incremental")
            << " stream → " << args.replicateTo
            << ":" << req.destDataset
            << rang::style::reset << std::endl;

  auto pipeline = ReplicatePure::buildReplicationPipeline(req);
  // 1.1.69: a failed send leaves no local snapshot behind — it would
  // otherwise be picked as the next base although the remote never
  // received it (what 1.1.48 fixed for `crate backup`).
  try {
    Util::execPipeline(pipeline,
                       "zfs send | ssh ... zfs recv",
                       /*stdinFile*/"", /*stdoutFile*/"");
  } catch (...) {
    try { Util::execCommand(BackupPure::buildDestroySnapshotArgv(req.sourceDataset, req.currSnapshotSuffix),
                            "zfs destroy snapshot"); }
    catch (...) {}
    throw;
  }

  std::cout << rang::fg::green
            << "replicate: " << args.replicateTarget << "@"
            << req.currSnapshotSuffix << " streamed to "
            << (req.ssh.user.empty() ? "" : (req.ssh.user + "@"))
            << req.ssh.host << ":" << req.destDataset
            << rang::style::reset << std::endl;
  return true;
}
