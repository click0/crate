// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Jid -> owner registry — pure data + serde.
//
// Records "operator <uid> created jail <name> at jid <jid>" so the
// privops authz gate can answer "is this caller allowed to act on this
// jid/name?" for the verbs whose request only carries a jid or a name
// (signal_jail, set_rctl, set_jail_cpuset, query_jail_rctl, destroy_jail).
//
// This module is pure: it just holds the in-memory map and converts to
// and from a stable textual on-disk format. The side-effectful piece
// (file I/O + thread-safe mutator + bootstrap from live JailQuery) lives
// in lib/jid_owner_registry.{h,cpp}, which the daemon owns.
//
// On-disk format: one entry per line, four tab-separated columns:
//
//     <jid>\t<uid>\t<name>\t<path>\n
//
// Numbers are decimal; `name` and `path` use the upstream validator
// rules (alnum + ._-/, no tabs/newlines), so no escaping is needed. A
// blank line or a line starting with `#` is ignored (room for headers /
// future comments). Strict parse: any non-conforming non-comment line
// produces an error so a corrupted registry surfaces loudly instead of
// silently losing entries.

#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace JidOwnerRegistryPure {

struct Entry {
  uint32_t    uid  = 0;     // operator uid recorded at create_jail
  std::string name;          // jail name (kernel jail.name)
  std::string path;          // jail path (kernel jail.path, absolute)
};

// jid -> entry. std::map keeps entries sorted by jid, which makes the
// serialized form stable across runs (good for diffs and for tests).
using EntryMap = std::map<unsigned, Entry>;

// Render `entries` to the on-disk text form documented above. Always
// ends with a trailing newline if non-empty.
std::string serialize(const EntryMap &entries);

// Parse `text` produced by serialize(). On success returns true with
// `out` populated; on the first malformed non-comment line returns
// false with `err` describing the line number + reason and `out`
// cleared (fail closed).
bool parse(const std::string &text, EntryMap &out, std::string &err);

// Look up an entry by jail name. Returns true with `jidOut` and
// `entryOut` set on hit; false on miss. Linear scan — the registry is
// small (a host runs O(10²) jails at most) and lookup happens once per
// privops verb, not in any hot path.
bool lookupByName(const EntryMap &entries, const std::string &name,
                  unsigned &jidOut, Entry &entryOut);

// Find the entry whose `path` is a prefix of `query` (slash-anchored:
// query equals entry.path OR query starts with `entry.path + "/"`).
// On multiple matches returns the LONGEST entry.path so that nested
// jails resolve to the inner one rather than the outer one. Used by
// the privops authz layer for path-scoped verbs (mount_nullfs target,
// devfs mount_path) where the request carries a path that should lie
// inside an owned jail. Returns false on no match.
bool findOwnerByPath(const EntryMap &entries, const std::string &query,
                     unsigned &jidOut, Entry &entryOut);

} // namespace JidOwnerRegistryPure
