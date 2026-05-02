// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for the global inter-container DNS service. The per-
// stack DNS in lib/stack.cpp covers containers within one stack;
// this module covers the *host-wide* `.crate` zone so containers in
// different stacks (or with no stack at all) can resolve each other
// by name.
//
// Design: the runtime (lib/inter_dns.cpp) walks JailQuery for all
// crate-managed jails, builds a list of (name, ip4, ip6) entries,
// and asks this module to render an unbound include-fragment or a
// /etc/hosts file. Both formats are zero-config consumable by the
// resolvers most operators already run.
//

#include <string>
#include <vector>

namespace InterDnsPure {

struct Entry {
  std::string name;   // jail name, validated as hostname
  std::string ip4;    // empty if no IPv4
  std::string ip6;    // empty if no IPv6
};

// Validate a jail name as an RFC 1123 hostname label. Rules:
//   - non-empty, ≤63 chars
//   - first character: letter or digit
//   - last character:  letter or digit
//   - body characters: letters, digits, hyphen
//   - case-insensitive (we lower-case for normalisation)
// Returns "" on success, otherwise a one-line reason.
std::string validateHostname(const std::string &name);

// Lower-case a hostname for canonical comparison.
std::string normalizeName(const std::string &name);

// Render an unbound include fragment for the `.crate.` zone. Output:
//
//   server:
//     local-zone: "crate." static
//     local-data: "alpha.crate. IN A 10.0.0.1"
//     local-data: "alpha.crate. IN AAAA fd00::1"
//     ...
//
// Entries are sorted by name so the file diffs cleanly between
// rebuilds. Empty IPs are skipped (no record emitted), so a v4-only
// jail produces only one A line.
std::string buildUnboundFragment(const std::vector<Entry> &entries);

// Render a /etc/hosts-format block with a stable header/footer pair
// so a host-side rebuild can find and replace the section atomically.
// Layout:
//
//   # >>> crate inter-container DNS <<<
//   10.0.0.1   alpha.crate alpha
//   ...
//   # <<< crate inter-container DNS >>>
//
// Entries with no IPv4 emit an IPv6 line instead.
std::string buildHostsBlock(const std::vector<Entry> &entries);

// Replace any existing crate block inside `existing` with `block`.
// If no block is present, append `block` to a trailing newline.
// Used by the runtime to update /etc/hosts without scrambling the
// rest of the file.
std::string replaceHostsBlock(const std::string &existing,
                              const std::string &block);

} // namespace InterDnsPure
