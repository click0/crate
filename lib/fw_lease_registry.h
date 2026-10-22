// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.57: daemon-owned, thread-safe wrapper around FwLeasePure that also
// performs the sysctl side effects: when the first lease asking for
// IPv4 (IPv6) forwarding arrives and the sysctl is 0, it is switched on
// and the original value remembered in the state file; when the last
// such lease goes (release, destroy_jail, or a reconcile that finds the
// jail dead) the original value is restored. The state file survives a
// daemon restart so the restore still happens for leases taken before it.
//
// The sysctl accessors are injected so the class compiles and is
// testable without FreeBSD; daemon/main.cpp passes Util::getSysctlInt /
// Util::setSysctlInt.

#pragma once

#include "fw_lease_pure.h"

#include <functional>
#include <mutex>
#include <string>

class FwLeaseRegistry {
 public:
  struct SysctlIo {
    std::function<int(const char *name)>              get;
    std::function<void(const char *name, int value)>  set;
  };

  struct Result {
    int      slot = -1;
    unsigned fwd4Users = 0;
    unsigned fwd6Users = 0;
    bool     released = false;   // release(): a lease existed
  };

  // Loads `path` (missing file = empty state; a malformed file throws so
  // the operator notices). No sysctl is touched by the constructor.
  FwLeaseRegistry(std::string path, SysctlIo io);

  // Returns an error string ("" on success) and fills `out`.
  std::string acquire(unsigned jid, bool wantSlot, bool want4, bool want6, Result &out);
  Result release(unsigned jid);

  // Drop leases of dead jails (and restore the sysctls if that empties
  // a refcount). Returns the number dropped.
  void   setLiveProbe(std::function<bool(unsigned jid)> probe);
  size_t reconcile();

  size_t size() const;

 private:
  void applyTransitionLocked_(const FwLeasePure::Transition &t);
  void persistLocked_() const;

  std::string                        path_;
  SysctlIo                           io_;
  std::function<bool(unsigned)>      probe_;
  mutable std::mutex                 m_;
  FwLeasePure::State                 state_;
};
