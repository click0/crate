// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// 1.1.69: an advisory flock(2) on a jail directory for as long as the
// process that is populating or running it lives.
//
// `crate run` creates jail-<name>-<hex> (and `crate create` its
// chroot-create-<name>-<hex>) and fills it for seconds to minutes before
// any jail exists for it. `crate clean` swept every such directory that
// was not a RUNNING jail's root — so a clean during an extract deleted
// the container from under the run. The directory itself carries the
// lock: run/create hold it (close-on-exec, so nothing inside the jail
// inherits it; released by the kernel when the process exits, however
// it exits) and clean tries LOCK_EX|LOCK_NB first — EWOULDBLOCK means
// "in use", skip. A lock on a directory fd is ordinary FreeBSD flock(2).
//

#include <string>

namespace DirLock {

// Holds the lock for the object's lifetime. `path` must be an existing
// directory. Throws Exception when the directory cannot be opened or is
// already locked by another process (someone else is using it).
class Guard {
public:
  Guard() = default;
  explicit Guard(const std::string &path) { acquire(path); }
  ~Guard() { release(); }
  Guard(const Guard &) = delete;
  Guard &operator=(const Guard &) = delete;
  void acquire(const std::string &path);
  void release();
  bool held() const { return fd_ >= 0; }
private:
  int fd_ = -1;
};

// True when another process holds the lock on `path` (a run or create
// in progress). False when it is free — or cannot be opened at all (the
// caller then decides from stat(2) what to do with it).
bool isLocked(const std::string &path);

} // namespace DirLock
