// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Mount: allows to mount/unmount directories, and it auto-unmounts them from its destructor on error
//

#include <string>

class Mount {
  bool mounted = false;
  const char *fstype;
  std::string fspath;
  std::string target;
  int flags;

public:
  Mount(const char *newFstype, const std::string &newFspath, const std::string &newTarget, int newFlags = 0);
  ~Mount();

  void mount();
  void unmount(bool doThrow = true); // unmount is normally called individually, or as part of a destructor when exception has orrurred
};
