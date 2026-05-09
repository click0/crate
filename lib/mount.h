// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Mount: allows to mount/unmount directories, and it auto-unmounts
// them from its destructor on error.
//
// 0.9.19: when constructed for fstype="nullfs" AND a privops socket
// is detected (CRATE_PRIVOPS_SOCKET env or default path), mount()
// and unmount() route through `crated`'s mount_nullfs / unmount_nullfs
// privops verbs instead of calling nmount(2)/unmount(2) directly.
// The detection happens once at construction; later environment
// changes don't affect a live Mount object.
// Other fstypes (devfs, unionfs) always use nmount(2) — those verbs
// don't exist in the 0.9.0 taxonomy yet. MNT_IGNORE is dropped on
// the privops path (daemon's mount_nullfs verb doesn't carry
// arbitrary mount flags); operators using privops mode see the
// nullfs mounts in mount(8) output. Accept that trade-off; a
// future verb extension can pass flags through.
//

#include <string>

class Mount {
  bool mounted = false;
  const char *fstype;
  std::string fspath;
  std::string target;
  int flags;
  // 0.9.19: cached privops socket path; empty means "use nmount(2)"
  std::string privopsSocket_;

public:
  Mount(const char *newFstype, const std::string &newFspath, const std::string &newTarget, int newFlags = 0);
  ~Mount();

  void mount();
  void unmount(bool doThrow = true); // unmount is normally called individually, or as part of a destructor when exception has orrurred
};
