// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Daemon-owned, thread-safe wrapper around JidOwnerRegistryPure.
//
// Holds the live jid->owner map and persists it to disk so a daemon
// restart doesn't drop authorization state for jails that survived.
// Construction loads the file (if any); every mutation atomically
// re-writes it (temp file + rename, so a torn write can never corrupt
// the live file). All methods are safe to call from multiple threads.
//
// The pure layer (lib/jid_owner_registry_pure.{h,cpp}) owns the data
// model + on-disk format; this layer only adds locking and I/O.

#pragma once

#include "jid_owner_registry_pure.h"
#include "privops_authz_pure.h"

#include <mutex>
#include <string>

class JidOwnerRegistry {
 public:
  // `path` is the on-disk TSV (typically /var/db/crate/jid_owners.tsv).
  // Constructor never throws on a missing file — the registry just
  // starts empty. A malformed existing file IS surfaced (throws), so an
  // operator notices instead of silently losing entries.
  explicit JidOwnerRegistry(std::string path);

  // Record a jail the daemon just created. Idempotent: re-recording
  // with the same jid replaces the entry (covers a pathological case
  // where the kernel reuses a jid we didn't get to forget yet).
  void recordCreate(unsigned jid, uint32_t uid,
                    const std::string &name, const std::string &path);

  // Forget a jail by jid. Returns true if an entry was removed.
  bool forgetByJid(unsigned jid);

  // Forget a jail by name (DestroyJail carries the name, not the jid).
  // Returns true if an entry was removed.
  bool forgetByName(const std::string &name);

  // Look up by jid. Returns {known=false} on miss.
  PrivOpsAuthzPure::Owner lookupByJid(unsigned jid) const;

  // Look up by jail name. Returns {known=false} on miss.
  PrivOpsAuthzPure::Owner lookupByName(const std::string &name) const;

  // Look up by path — longest-prefix, slash-anchored: `path` is owned
  // by jail J if path == J.path or starts with J.path + "/".
  // Returns {known=false} when no registered jail's path is a prefix
  // of `path` (the bootstrap concession applies at the authz layer).
  PrivOpsAuthzPure::Owner lookupByPath(const std::string &path) const;

  // Build an OwnerLookup that the privops authz layer can call. The
  // returned struct captures `this` by reference — the registry must
  // outlive the lookup (true in crated's main thread lifetime).
  PrivOpsAuthzPure::OwnerLookup makeLookup() const;

  // Convenience for the bootstrap path in daemon/main.cpp and for
  // tests. Number of entries currently held.
  size_t size() const;

 private:
  std::string                              path_;
  JidOwnerRegistryPure::EntryMap           entries_;
  mutable std::mutex                       m_;

  // Caller MUST hold `m_`. Atomic write: tmpfile + rename.
  void persistLocked_() const;
};
