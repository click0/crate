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
// 1.1.78: *ownXCookieFile — the host Xauthority file of the X server
// this run started (nested / headless / gpu), "" otherwise; the caller
// hands it to the jail with installOwnXCookie once the jail's mounts
// are in place.
RunAtEnd setupX11(const Spec &spec, const std::string &jailPath,
                  const std::string &jailXname,
                  std::list<std::unique_ptr<Mount>> &mounts,
                  std::function<void(const std::string&, const std::string&)> setJailEnv,
                  bool logProgress, std::string *ownXCookieFile = nullptr);

// 1.1.78: copy that cookie into the jail and return its path there (the
// jail's XAUTHORITY). 0600 and owned by uid:gid — the user the command
// runs as — when crate may chown ((uid_t)-1: leave it to the jail's
// root); 0644 when it may not (rootless with a run/user that is not the
// operator). The display is the jail's own either way.
std::string installOwnXCookie(const std::string &jailPath, const std::string &hostCookieFile,
                              uid_t uid, gid_t gid);

// Set up clipboard proxy, returns cleanup callback
RunAtEnd setupClipboard(const Spec &spec, const std::string &jailXname,
                        const std::string &jidStr, bool logProgress);

// gui.mode: compositor — launch a Wayland compositor *inside* the jail
// (headless+VNC or DRM/KMS, per gui.backend). Must run after the jail
// exists (jid known), unlike setupX11 which runs pre-jail. Returns a
// cleanup callback that tears down the compositor (and wayvnc, if any).
RunAtEnd setupCompositor(const Spec &spec, const std::string &jailPath,
                         const std::string &jailXname,
                         const std::string &jidStr,
                         std::list<std::unique_ptr<Mount>> &mounts,
                         std::function<void(const std::string&, const std::string&)> setJailEnv,
                         bool logProgress);

// Set up D-Bus isolation
void setupDbus(const Spec &spec, const std::string &jailPath,
               std::function<void(const std::string&, const std::string&)> setJailEnv,
               bool logProgress);

// Copy X11 authentication files into jail
void copyX11Auth(const Spec &spec, const std::string &jailPath,
                 const std::string &homeDir, uid_t uid, gid_t gid);

}
