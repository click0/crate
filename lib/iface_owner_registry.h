// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Interface -> owner registry (1.1.43) — the daemon-owned, thread-safe,
// persisted wrapper around IfaceOwnerRegistryPure. Same shape as
// lib/jid_owner_registry.h: recorded on a successful create_epair (both
// halves, the peer uid), forgotten on teardown_iface (both halves),
// reconciled against the host's live interface list at startup and on
// every lookup hit, and exposed to the privops authz gate through
// OwnerLookup::byIface.

#pragma once

#include "iface_owner_registry_pure.h"
#include "privops_authz_pure.h"

#include <mutex>
#include <string>

class IfaceOwnerRegistry {
 public:
  // `path` is the on-disk TSV (typically /var/db/crate/iface_owners.tsv).
  // A missing file is an empty registry; a malformed one throws.
  explicit IfaceOwnerRegistry(std::string path);

  // Record both halves of a freshly created epair for `uid`.
  void recordEpair(const std::string &ifaceA, const std::string &ifaceB, uint32_t uid);

  // Forget an interface and its peer half. Returns true if anything
  // was removed.
  bool forgetPair(const std::string &ifname);

  // Look up one interface. {known=false} on miss.
  PrivOpsAuthzPure::Owner lookup(const std::string &ifname) const;

  // Live probe (true iff the interface exists on the host) — see the
  // pure header for why it is asked about the host half.
  void setLiveProbe(IfaceOwnerRegistryPure::LiveProbe probe);
  size_t reconcile();

  size_t size() const;

 private:
  std::string                        path_;
  IfaceOwnerRegistryPure::EntryMap   entries_;
  IfaceOwnerRegistryPure::LiveProbe  probe_;
  mutable std::mutex                 m_;

  bool dropIfStaleLocked_(IfaceOwnerRegistryPure::EntryMap::iterator it) const;
  void persistLocked_() const;
};
