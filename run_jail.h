// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#pragma once

#include "util.h"

#include <string>
#include <vector>
#include <functional>

#include <unistd.h>

namespace RunJail {

struct JailInfo {
  int jid;
  int jailFd; // owning descriptor (FreeBSD 15.0+), or -1
};

// Create a jail using jail_setv() C API
JailInfo createJail(const class Spec &spec, const std::string &jailPath, bool logProgress);

// Remove a jail (race-free via descriptor if available)
void removeJail(const JailInfo &info);

// Apply RCTL resource limits, returns cleanup callback
RunAtEnd applyRctlLimits(const class Spec &spec, int jid, bool logProgress);

// Attach ZFS datasets to jail, returns cleanup callback
RunAtEnd attachZfsDatasets(const class Spec &spec, int jid, bool logProgress);

// Create user, group, home directory inside jail
void createUserInJail(const class Spec &spec, const std::string &jailPath, int jid,
                      const std::string &user, const std::string &homeDir,
                      uid_t uid, gid_t gid,
                      const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail,
                      const std::function<void(const char*)> &runScript,
                      bool logProgress);

}
