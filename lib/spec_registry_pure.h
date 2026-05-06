// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for the crate spec registry (0.8.21).
//
// The registry maps {jail name -> absolute path of the .crate file
// that started it}. It exists so the daemon's control-plane
// PostStart endpoint can reach for the spec without the operator
// having to re-supply -f every time. Pre-0.8.21 control sockets
// returned 501 for /start because crated didn't know which file
// to feed back into `crate run`.
//
// Storage: /var/run/crate/spec-registry.txt
// Format:  one "<jail-name> <abs-crate-path>" per line; lines
//          starting with `#` and empty lines are ignored. Same
//          flock-protected atomic-rename pattern as
//          /var/run/crate/network-leases.txt — pure helpers here
//          own parse/format + validation; lib/spec_registry.cpp
//          owns the file I/O.
//
// Lifetime: registered when `crate run -f <file>` successfully
// starts a jail; intentionally NOT auto-removed when the jail
// stops, so a follow-up control-socket PostStart can find the
// path. `crate clean --orphans` (future) removes entries whose
// path no longer exists.
//

#include <string>
#include <vector>

namespace SpecRegistryPure {

struct Entry {
  std::string name;       // jail name (alphanumeric + _-, 1..63)
  std::string cratePath;  // absolute path on the host filesystem
};

// --- Validators (return "" on success) ---

// Jail name: alphanumeric + _-, length 1..63, no leading dash/dot.
// Same constraints as VmWrapPure::validateJailName so operators
// can reuse the same naming.
std::string validateName(const std::string &n);

// Absolute path validator.
//   - must start with '/'
//   - no `..` segments
//   - no shell metas / control chars
//   - length 1..1024
// We do NOT require the path to end in `.crate` because operators
// occasionally use bare YAML or other extensions; the daemon
// will let `crate run` reject unsuitable inputs at exec time.
std::string validatePath(const std::string &p);

// One-shot entry validator.
std::string validateEntry(const Entry &e);

// --- File format ---

// Parse one registry line "<name> <path>". Returns "" on success.
// Accepts a single space (only) as separator — no tabs, no
// multiple spaces. Tightened so a malformed line can't sneak a
// fake path past validatePath via shell quoting tricks.
std::string parseLine(const std::string &line, Entry &out);

// Format one line; no trailing newline (caller adds it).
std::string formatLine(const Entry &e);

// --- Lookups ---

// Linear search of `entries` for `name`. Returns iterator-style:
// the index, or -1 if not found.
int findIndex(const std::vector<Entry> &entries, const std::string &name);

} // namespace SpecRegistryPure
