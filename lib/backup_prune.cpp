// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// Runtime side of `crate backup-prune`. Scans a directory for
// .zstream files left by `crate backup`, applies the operator's
// retention policy via BackupPrunePure::decidePrune, and unlinks
// the rejects. All policy decisions live in the pure module.
//

#include "args.h"
#include "backup_prune_pure.h"
#include "backup_pure.h"
#include "commands.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#define ERR(msg...) ERR2("backup-prune", msg)

namespace fs = std::filesystem;

namespace {

// Sum the on-disk size of a list of basenames inside `dir`. Best-effort
// — files that disappeared between scan and stat just contribute 0.
double totalMegabytes(const std::string &dir,
                      const std::vector<std::string> &names) {
  double total = 0;
  for (const auto &n : names) {
    struct stat st{};
    if (::stat((dir + "/" + n).c_str(), &st) == 0)
      total += static_cast<double>(st.st_size);
  }
  return total / (1024.0 * 1024.0);
}

} // anon

bool backupPruneCrate(const Args &args) {
  // Validate inputs.
  if (auto e = BackupPrunePure::validateDir(args.backupPruneDir); !e.empty())
    ERR(e)
  if (!args.backupPruneJailFilter.empty())
    if (auto e = BackupPrunePure::validateJailFilter(args.backupPruneJailFilter); !e.empty())
      ERR(e)
  if (args.backupPruneKeep.empty())
    ERR("--keep <retention-spec> is required (e.g. daily=7,weekly=4)")

  BackupPure::RetentionPolicy policy;
  if (auto e = BackupPure::parseRetention(args.backupPruneKeep, policy); !e.empty())
    ERR(e)

  if (!Util::Fs::dirExists(args.backupPruneDir))
    ERR("directory does not exist: " << args.backupPruneDir)

  // Scan the directory.
  std::vector<BackupPrunePure::StreamFile> files;
  unsigned skipped = 0;
  for (const auto &entry : fs::directory_iterator(args.backupPruneDir)) {
    if (!entry.is_regular_file()) continue;
    auto basename = entry.path().filename().string();
    BackupPrunePure::StreamFile sf;
    std::string parseErr;
    if (!BackupPrunePure::parseStreamFilename(basename, sf, parseErr)) {
      // Silently skip non-matching files — the directory may contain
      // README.md, .DS_Store, an external tool's output, etc. The
      // pure parser already distinguishes "looks like ours but
      // malformed" from "doesn't look like ours at all" by the error
      // text but we collapse both here: if it doesn't fit our schema,
      // we don't touch it.
      skipped++;
      continue;
    }
    if (!args.backupPruneJailFilter.empty()
        && sf.jailName != args.backupPruneJailFilter) {
      skipped++;
      continue;
    }
    files.push_back(sf);
  }

  if (files.empty()) {
    std::cerr << rang::fg::yellow << "backup-prune: no matching .zstream files in "
              << args.backupPruneDir
              << rang::style::reset << std::endl;
    return true;
  }

  auto decision = BackupPrunePure::decidePrune(files, policy,
                                               args.backupPruneDeleteOrphans);

  // Reporting.
  std::cout << rang::style::bold
            << "backup-prune: directory=" << args.backupPruneDir
            << " keep=" << args.backupPruneKeep
            << (args.backupPruneJailFilter.empty()
                ? std::string("")
                : std::string(" jail=") + args.backupPruneJailFilter)
            << (args.backupPruneDryRun ? " [DRY-RUN]" : "")
            << rang::style::reset << std::endl;

  std::cout << "  scanned: "  << files.size() << " stream(s); skipped non-matching: " << skipped << std::endl;
  std::cout << rang::fg::green
            << "  keep:    " << decision.keep.size() << " file(s) ("
            << (long)totalMegabytes(args.backupPruneDir, decision.keep) << " MB)"
            << rang::style::reset << std::endl;
  std::cout << rang::fg::red
            << "  remove:  " << decision.remove.size() << " file(s) ("
            << (long)totalMegabytes(args.backupPruneDir, decision.remove) << " MB)"
            << rang::style::reset << std::endl;
  if (!decision.orphans.empty())
    std::cout << rang::fg::yellow
              << "  orphans: " << decision.orphans.size()
              << " file(s) (incremental without surviving base; pass"
                 " --delete-orphans to remove)"
              << rang::style::reset << std::endl;

  for (const auto &name : decision.remove) {
    if (args.backupPruneDryRun) {
      std::cout << "  - would remove: " << name << std::endl;
    } else {
      try {
        Util::Fs::unlink(args.backupPruneDir + "/" + name);
        std::cout << "  - removed: " << name << std::endl;
      } catch (const std::exception &ex) {
        std::cerr << rang::fg::red
                  << "  ! failed to remove " << name << ": " << ex.what()
                  << rang::style::reset << std::endl;
      }
    }
  }

  for (const auto &name : decision.orphans) {
    std::cout << rang::fg::yellow
              << "  ? orphan: " << name
              << rang::style::reset << std::endl;
  }

  return true;
}
