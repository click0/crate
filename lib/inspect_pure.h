// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for `crate inspect TARGET` — produces a single JSON
// document describing a running container's runtime state. Callers
// (lib/inspect.cpp) gather the raw data via JailQuery, sysctl,
// rctl(8), and zfs(8); this module assembles the JSON and ensures
// consistent escaping/formatting that diff-tools can parse cleanly.
//

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace InspectPure {

// One mount entry: source -> target (matches mount(8) output).
struct Mount {
  std::string source;
  std::string target;
  std::string fstype;
};

// One network interface visible to the jail.
struct Interface {
  std::string name;
  std::string ip4;        // empty if none
  std::string ip6;
  std::string mac;
};

// Snapshot of everything `crate inspect` reports. Fields with empty
// strings / zero-length lists are still emitted (as `""` / `[]`)
// so the JSON shape is stable across containers — easier to diff.
struct InspectData {
  // --- Identity ---
  std::string name;
  int jid = 0;
  std::string hostname;
  std::string path;       // jail root on host
  std::string osrelease;  // host kernel release

  // --- Configuration (from jail(8) params) ---
  std::map<std::string, std::string> jailParams;

  // --- Runtime state ---
  std::vector<Interface> interfaces;
  std::vector<Mount>     mounts;
  std::map<std::string, std::string> rctlUsage; // raw rctl -u key=value
  std::string zfsDataset;     // empty if not on ZFS
  std::string zfsOrigin;      // for clones, empty otherwise
  unsigned   processCount = 0;

  // --- GUI session (if any) ---
  bool hasGui = false;
  int  guiDisplay = 0;
  int  guiVncPort = 0;
  int  guiWsPort  = 0;
  std::string guiMode;

  // --- Timestamps ---
  long startedAt = 0;     // UNIX epoch when the jail was created
  long inspectedAt = 0;   // UNIX epoch when the snapshot was taken
};

// Render the InspectData as a pretty-printed JSON document with a
// stable key order. Always ends with a single newline so command-
// line consumers don't see a half-line. Uses 2-space indentation.
std::string renderJson(const InspectData &d);

// JSON-escape a string per RFC 8259 §7. Handles ", \, control
// characters (0x00..0x1F as \u00XX) and passes UTF-8 ≥0x80 through
// unchanged. Public so other modules and tests can reuse it.
std::string escapeJsonString(const std::string &in);

// Parse the `key=value\n...` output from `rctl -u jail:N` into the
// map in `data.rctlUsage`. Tolerates blank lines and lines without
// '=' (silently skipped).
void applyRctlOutput(const std::string &rctlOut, InspectData &data);

// Parse the `mount` command output (FreeBSD format:
// `<source> on <target> (<fstype>, ...)`) and append entries to
// `data.mounts`. Filters to entries whose target starts with
// `<jailRoot>/` so we don't capture host-side mounts.
void applyMountOutput(const std::string &mountOut,
                      const std::string &jailRoot,
                      InspectData &data);

} // namespace InspectPure
