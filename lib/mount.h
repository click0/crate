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
// 1.1.63 / 1.1.76: tmpfs and devfs too (mount_tmpfs, mount_devfs; the
// unmount is unmount_nullfs for all three). unionfs always uses
// nmount(2) — there is no verb for it. MNT_IGNORE is dropped on
// the privops path for nullfs and tmpfs (the verbs don't carry
// arbitrary mount flags; mount_devfs always sets it); operators using
// privops mode see those mounts in mount(8) output. Accept that trade-off; a
// future verb extension can pass flags through.
//

#include <string>
#include <utility>
#include <vector>

class Mount {
  bool mounted = false;
  const char *fstype;
  std::string fspath;
  std::string target;
  int flags;
  // 0.9.19: cached privops socket path; empty means "use nmount(2)"
  std::string privopsSocket_;
  // 1.1.63: extra nmount(2) string parameters (tmpfs: size, uid, gid,
  // mode); carried to the mount_tmpfs privops verb under rootless
  std::vector<std::pair<std::string, std::string>> params_;

public:
  Mount(const char *newFstype, const std::string &newFspath, const std::string &newTarget, int newFlags = 0);
  ~Mount();

  // 1.1.63: add a string parameter before mount(); tmpfs only today
  void addParam(const std::string &name, const std::string &value);

  void mount();
  void unmount(bool doThrow = true); // unmount is normally called individually, or as part of a destructor when exception has orrurred
};
