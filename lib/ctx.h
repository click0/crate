// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

#include <unistd.h>

#include <map>
#include <memory>
#include <set>
#include <string>

namespace Ctx {

class FwUsers {
  int fd; // lock
  std::set<pid_t> pids;
  bool inMemory;
  bool changed;
public:
  FwUsers();
  ~FwUsers();
  static std::unique_ptr<FwUsers> lock();  // lock, open, and read
  void unlock();            // unlock, close, and possibly save
  bool isEmpty() const;
  void add(pid_t pid);
  void del(pid_t pid);
  // 1.1.27: drop entries whose pid no longer exists (kill(pid,0) →
  // ESRCH). FwSlots always had this; FwUsers did not, so a `crate run`
  // killed without teardown (SIGKILL/OOM/panic) left its pid here
  // forever, isEmpty() was never true again, and the shared NAT rule +
  // net.inet.ip.forwarding were never restored. Loads the file first if
  // needed; marks the file dirty only when something was removed.
  void garbageCollect();
private:
  static std::string file();
  void readIntoMemory();
  void writeToFile() const;
};

// Dynamic ipfw rule slot allocator (§18):
// Eliminates rule conflicts by assigning unique rule number slots to each
// running crate instance, tracked in /var/run/crate/ctx-fw-slots.
class FwSlots {
  int fd;
  std::map<pid_t, unsigned> slots; // pid -> slot number
  bool inMemory;
  bool changed;
public:
  FwSlots();
  ~FwSlots();
  static std::unique_ptr<FwSlots> lock();
  void unlock();
  unsigned allocate(pid_t pid);  // returns a unique slot number (0-based)
  void release(pid_t pid);
private:
  static std::string file();
  void readIntoMemory();
  void writeToFile() const;
  void garbageCollect();         // remove dead PIDs
};

}
