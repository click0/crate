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

  // Plan: full vs. incremental.
  BackupPure::Inputs in;
  in.sinceProvided = !args.replicateSince.empty();
  in.sinceName     = args.replicateSince;
  if (!in.sinceProvided && args.replicateAutoIncremental) {
    auto prev = ZfsDataset::findLatestBackupSuffix(req.sourceDataset);
    if (!prev.empty()) {
      in.priorBackupExists   = true;
      in.priorSnapshotSuffix = prev;
    }
  }
  auto plan = BackupPure::choosePlan(in, args.replicateAutoIncremental);
  if (plan.kind == BackupPure::Plan::Kind::Error)
    ERR(plan.reason)

  req.currSnapshotSuffix = BackupPure::snapshotSuffix(::time(nullptr));
  req.prevSnapshotSuffix =
    (plan.kind == BackupPure::Plan::Kind::Incremental) ? plan.sinceSuffix : "";

  // SSH transport spec.
  if (auto e = ReplicatePure::parseSshRemote(args.replicateTo, req.ssh);
      !e.empty())
    ERR("--to: " << e)
  req.ssh.port         = args.replicateSshPort;
  req.ssh.identityFile = args.replicateSshKey;
  req.ssh.configFile   = args.replicateSshConfig;
  req.ssh.extraOpts    = args.replicateSshOpts;

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
  Util::execPipeline(pipeline,
                     "zfs send | ssh ... zfs recv",
                     /*stdinFile*/"", /*stdoutFile*/"");

  std::cout << rang::fg::green
            << "replicate: " << args.replicateTarget << "@"
            << req.currSnapshotSuffix << " streamed to "
            << (req.ssh.user.empty() ? "" : (req.ssh.user + "@"))
            << req.ssh.host << ":" << req.destDataset
            << rang::style::reset << std::endl;
  return true;
}
