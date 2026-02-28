// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

#include <string>
#include <vector>

namespace Config {

struct Settings {
  // Paths
  std::string prefix;             // default: /var/run/crate
  std::string cache;              // default: /var/cache/crate
  std::string logs;               // default: /var/log/crate

  // ZFS
  bool zfsEnable;                 // default: false
  std::string zfsZpool;           // default: ""
  std::string zfsOptions;         // default: "-o compress=lz4 -o atime=off"

  // Networking
  std::string networkInterface;   // default: "" (auto-detect)

  // Base system
  std::string bootstrapMethod;    // default: "base_txz"

  // Security defaults
  int securelevel;                // default: 2
  int childrenMax;                // default: 0

  // Search path for .crate files
  std::vector<std::string> searchPath;

  // Compression
  std::string compressXzOptions;  // default: "-T0"
};

// Load configuration, merging system + user files
// Locations (in priority order):
//   /usr/local/etc/crate.yml   (system-wide)
//   ~/.config/crate/crate.yml  (user override, higher priority)
const Settings& load();

// Get the singleton (must call load() first or returns defaults)
const Settings& get();

// Resolve a .crate file name using search path
std::string resolveCrateFile(const std::string &name);

}
