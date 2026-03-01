// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

#include <unistd.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace Ctx {

// GUI session entry: tracks one running X server (Xephyr or Xvfb) for a crate jail
struct GuiEntry {
  pid_t ownerPid;       // crate process PID that owns this session
  unsigned displayNum;  // X display number (:10, :11, ...)
  pid_t xServerPid;     // Xephyr or Xvfb PID
  unsigned vncPort;     // VNC port (0 = no VNC), e.g. 5910
  unsigned wsPort;      // websockify port (0 = no noVNC), e.g. 6010
  std::string mode;     // "nested" (Xephyr), "headless" (Xvfb), "shared"
  std::string jailName; // jail name (e.g. "jail-firefox-abc123")
};

// Lockfile-based GUI registry, following the FwSlots pattern from ctx.h.
// Tracks display number allocations and X server sessions in
// /var/run/crate/ctx-gui-registry.
class GuiRegistry {
  int fd;
  std::map<pid_t, GuiEntry> entries; // ownerPid -> entry
  bool inMemory;
  bool changed;
  GuiRegistry();
public:
  ~GuiRegistry();
  static std::unique_ptr<GuiRegistry> lock();
  void unlock();

  // Allocate the next available display number (starting from 10)
  unsigned allocateDisplay(pid_t ownerPid);

  // Register a full GUI session entry
  void registerEntry(const GuiEntry &entry);

  // Unregister by owner PID
  void unregisterEntry(pid_t ownerPid);

  // Get all current entries (after garbage collection)
  std::vector<GuiEntry> getEntries();

  // Find entry by jail name (partial match supported)
  const GuiEntry* findByTarget(const std::string &target) const;

private:
  static std::string file();
  void readIntoMemory();
  void writeToFile() const;
  void garbageCollect();
};

}
