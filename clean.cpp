// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#include "args.h"
#include "locs.h"
#include "pathnames.h"
#include "ctx.h"
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

// Collect JIDs of all running jails
static std::set<int> getRunningJailJids() {
  std::set<int> jids;
  std::string output;
  try {
    output = Util::execCommandGetOutput({CRATE_PATH_JLS, "-N"}, "list jails");
  } catch (...) {
    return jids;
  }
  std::istringstream is(output);
  std::string line;
  bool header = true;
  while (std::getline(is, line)) {
    if (header) { header = false; continue; }
    if (line.empty()) continue;
    int jid;
    std::istringstream ls(line);
    if (ls >> jid)
      jids.insert(jid);
  }
  return jids;
}

// Collect paths of all running jail roots
static std::set<std::string> getRunningJailPaths() {
  std::set<std::string> paths;
  std::string output;
  try {
    output = Util::execCommandGetOutput({CRATE_PATH_JLS, "-N"}, "list jails");
  } catch (...) {
    return paths;
  }
  std::istringstream is(output);
  std::string line;
  bool header = true;
  while (std::getline(is, line)) {
    if (header) { header = false; continue; }
    if (line.empty()) continue;
    std::istringstream ls(line);
    int jid;
    std::string ip, hostname, path;
    ls >> jid >> ip >> hostname >> path;
    if (!path.empty())
      paths.insert(path);
  }
  return paths;
}

// Check if a PID is alive
static bool pidAlive(pid_t pid) {
  return (::kill(pid, 0) == 0);
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
