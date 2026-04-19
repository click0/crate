// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

#include "util.h"
#include "spec.h"
#include "mount.h"

#include <string>
#include <list>
#include <memory>
#include <functional>

namespace RunGui {

// Set up X11 access (shared, nested, or none), returns Xephyr cleanup callback
RunAtEnd setupX11(const Spec &spec, const std::string &jailPath,
                  const std::string &jailXname,
                  std::list<std::unique_ptr<Mount>> &mounts,
                  std::function<void(const std::string&, const std::string&)> setJailEnv,
                  bool logProgress);

// Set up clipboard proxy, returns cleanup callback
RunAtEnd setupClipboard(const Spec &spec, const std::string &jailXname,
                        const std::string &jidStr, bool logProgress);

// Set up D-Bus isolation
void setupDbus(const Spec &spec, const std::string &jailPath,
               std::function<void(const std::string&, const std::string&)> setJailEnv,
               bool logProgress);

// Copy X11 authentication files into jail
void copyX11Auth(const Spec &spec, const std::string &jailPath,
                 const std::string &homeDir, uid_t uid, gid_t gid);

}
