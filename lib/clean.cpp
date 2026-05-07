// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "locs.h"
#include "jail_query.h"
#include "pathnames.h"
#include "ctx.h"
#include "spec_registry.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#define ERR(msg...) \
  ERR2("clean", msg)

// Collect paths of all running jail roots (uses libjail API)
static std::set<std::string> getRunningJailPaths() {
  std::set<std::string> paths;
  for (auto &j : JailQuery::getAllJails())
    if (!j.path.empty())
      paths.insert(j.path);
  return paths;
}

bool cleanCrates(const Args &args) {
  bool dryRun = args.cleanDryRun;
  unsigned cleaned = 0;

  auto runningPaths = getRunningJailPaths();

  // 1. Clean orphaned jail directories under /var/run/crate/
  std::cout << rang::style::bold << "Scanning for orphaned jail directories..."
            << rang::style::reset << std::endl;
  {
    auto jailDir = std::string(Locations::jailDirectoryPath);
    DIR *dir = ::opendir(jailDir.c_str());
    if (dir) {
      struct dirent *ent;
      while ((ent = ::readdir(dir)) != nullptr) {
        std::string name = ent->d_name;
        if (name == "." || name == "..") continue;
        if (name.find("jail-") != 0) continue;
        auto fullPath = jailDir + "/" + name;
        struct stat sb;
        if (::stat(fullPath.c_str(), &sb) != 0 || !S_ISDIR(sb.st_mode))
          continue;
        // Check if this directory is a running jail root
        if (runningPaths.count(fullPath) > 0)
          continue;
        // Orphaned directory
        if (dryRun) {
          std::cout << "  [dry-run] would remove: " << fullPath << std::endl;
        } else {
          std::cout << "  removing: " << fullPath << std::endl;
          try {
            Util::Fs::rmdirHier(fullPath);
            cleaned++;
          } catch (const std::exception &e) {
            std::cerr << rang::fg::yellow << "  warning: failed to remove " << fullPath
                      << ": " << e.what() << rang::style::reset << std::endl;
          }
        }
      }
      ::closedir(dir);
    }
  }

  // 2. Clean stale interface directories
  std::cout << rang::style::bold << "Scanning for stale interface records..."
            << rang::style::reset << std::endl;
  {
    auto ifaceDir = std::string(Locations::jailDirectoryPath) + Locations::jailSubDirectoryIfaces;
    DIR *dir = ::opendir(ifaceDir.c_str());
    if (dir) {
      struct dirent *ent;
      while ((ent = ::readdir(dir)) != nullptr) {
        std::string name = ent->d_name;
        if (name == "." || name == "..") continue;
        auto fullPath = ifaceDir + "/" + name;
        // Check if parent jail still exists
        bool found = false;
        for (auto &p : runningPaths)
          if (p.find(name) != std::string::npos) { found = true; break; }
        if (found) continue;
        if (dryRun) {
          std::cout << "  [dry-run] would remove: " << fullPath << std::endl;
        } else {
          std::cout << "  removing: " << fullPath << std::endl;
          try {
            Util::Fs::rmdirFlat(fullPath);
            cleaned++;
          } catch (...) {
            // Ignore errors on interface cleanup
          }
        }
      }
      ::closedir(dir);
    }
  }

  // 3. Clean stale PID entries in ctx files
  std::cout << rang::style::bold << "Cleaning stale context entries..."
            << rang::style::reset << std::endl;
  {
    // FwUsers: remove dead PIDs
    try {
      auto fwUsers = Ctx::FwUsers::lock();
      // FwUsers internally does garbage collection on dead PIDs
      if (!dryRun)
        fwUsers->unlock();
      else {
        std::cout << "  [dry-run] would clean stale firewall user entries" << std::endl;
        fwUsers->unlock();
      }
    } catch (...) {
      // Context files may not exist yet — that's fine
    }

    // FwSlots: remove dead PIDs
    try {
      auto fwSlots = Ctx::FwSlots::lock();
      // FwSlots internally does garbage collection on dead PIDs
      if (!dryRun)
        fwSlots->unlock();
      else {
        std::cout << "  [dry-run] would clean stale firewall slot entries" << std::endl;
        fwSlots->unlock();
      }
    } catch (...) {
      // Context files may not exist yet — that's fine
    }
  }

  // 4. Clean stale COW overlay directories
  std::cout << rang::style::bold << "Scanning for stale COW overlays..."
            << rang::style::reset << std::endl;
  {
    auto jailDir = std::string(Locations::jailDirectoryPath);
    DIR *dir = ::opendir(jailDir.c_str());
    if (dir) {
      struct dirent *ent;
      while ((ent = ::readdir(dir)) != nullptr) {
        std::string name = ent->d_name;
        if (name.find("-cow-writable") == std::string::npos) continue;
        auto fullPath = jailDir + "/" + name;
        struct stat sb;
        if (::stat(fullPath.c_str(), &sb) != 0 || !S_ISDIR(sb.st_mode))
          continue;
        // The corresponding jail directory would be name without "-cow-writable"
        auto baseName = name.substr(0, name.find("-cow-writable"));
        auto basePath = jailDir + "/" + baseName;
        if (runningPaths.count(basePath) > 0)
          continue;
        if (dryRun) {
          std::cout << "  [dry-run] would remove: " << fullPath << std::endl;
        } else {
          std::cout << "  removing: " << fullPath << std::endl;
          try {
            Util::Fs::rmdirHier(fullPath);
            cleaned++;
          } catch (const std::exception &e) {
            std::cerr << rang::fg::yellow << "  warning: failed to remove " << fullPath
                      << ": " << e.what() << rang::style::reset << std::endl;
          }
        }
      }
      ::closedir(dir);
    }
  }

  // 5. Clean orphan spec-registry entries (0.8.34)
  // The registry maps {jail-name -> abs-path-of-.crate-file} and
  // is populated by `crate run -f` (since 0.8.21). Entries
  // intentionally persist past stop/restart so the daemon's
  // control-plane PostStart can find the path again. But when
  // the operator deletes the .crate file from disk, the entry
  // becomes a dangling pointer — PostStart returns 410 Gone,
  // confusingly. This section sweeps those.
  std::cout << rang::style::bold << "Scanning for spec-registry orphans..."
            << rang::style::reset << std::endl;
  {
    try {
      auto entries = SpecRegistry::readAll();
      for (const auto &e : entries) {
        struct stat sb;
        if (::stat(e.cratePath.c_str(), &sb) == 0) continue;  // file still there
        if (dryRun) {
          std::cout << "  [dry-run] would remove registry entry: "
                    << e.name << " -> " << e.cratePath
                    << " (file no longer exists)" << std::endl;
        } else {
          std::cout << "  removing registry entry: "
                    << e.name << " -> " << e.cratePath << std::endl;
          try {
            SpecRegistry::remove(e.name);
            cleaned++;
          } catch (const std::exception &ex) {
            std::cerr << rang::fg::yellow
                      << "  warning: failed to remove registry entry "
                      << e.name << ": " << ex.what()
                      << rang::style::reset << std::endl;
          }
        }
      }
    } catch (const std::exception &e) {
      // readAll throws on parse errors / permission issues — log,
      // don't abort the rest of the cleanup.
      std::cerr << rang::fg::yellow
                << "  warning: spec-registry read failed: " << e.what()
                << " (skipping orphan sweep)"
                << rang::style::reset << std::endl;
    }
  }

  // Summary
  std::cout << std::endl;
  if (dryRun) {
    std::cout << rang::fg::yellow << "Dry run complete. No changes made."
              << rang::style::reset << std::endl;
  } else {
    std::cout << rang::fg::green << "Cleanup complete: " << cleaned
              << " item" << (cleaned != 1 ? "s" : "") << " removed."
              << rang::style::reset << std::endl;
  }

  return true;
}
