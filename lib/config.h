// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

#include <string>
#include <vector>
#include <map>

namespace Config {

// Named network definition for use in jail specs via "network: <name>"
struct NetworkDef {
  std::string mode;           // "bridge", "passthrough", "netgraph"
  std::string bridge;         // for bridge mode (e.g. "bridge0")
  std::string interface;      // for passthrough/netgraph (e.g. "vtnet1", "em0")
  std::string gateway;        // gateway IP (e.g. "192.168.1.1")
  int vlan = -1;              // VLAN ID (1-4094), -1 = no VLAN
  bool staticMac = false;     // deterministic MAC address
  std::string ip6;            // "slaac", "none", or static IPv6 address
};

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
  std::string defaultBridge;      // default: "" (no default bridge for bridge mode)
  bool staticMacDefault;          // default: false (deterministic MAC for bridge/passthrough/netgraph)
  // CIDR pool for `network: auto` IP allocation (0.7.17). Empty
  // disables auto-allocation; specs using `network: auto` then
  // fall back to DHCP. Default unset — operators opt in by writing
  // `network_pool: 10.66.0.0/24` in /usr/local/etc/crate.yml or
  // ~/.config/crate/crate.yml.
  std::string networkPool;

  // Base system
  std::string bootstrapMethod;    // default: "base_txz"

  // Security defaults
  int securelevel;                // default: 2
  int childrenMax;                // default: 0

  // Search path for .crate files
  std::vector<std::string> searchPath;

  // Compression
  std::string compressXzOptions;  // default: "-T0"

  // Named networks (referenced by "network: <name>" in jail specs)
  std::map<std::string, NetworkDef> networks;
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
