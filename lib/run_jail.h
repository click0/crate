// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

#include "util.h"
#include "spec.h"

#include <map>
#include <string>
#include <vector>
#include <functional>

#include <unistd.h>

namespace RunJail {

struct JailInfo {
  int jid;
  int jailFd; // owning descriptor (FreeBSD 15.0+), or -1
};

// Create a jail using jail_setv() C API. When the privops socket
// is detected (CRATE_PRIVOPS_SOCKET env or default path), routes
// through the `create_jail` privops verb instead — caller must
// provide a stable `jailName` since the privops verb identifies
// jails by name (the kernel auto-names libjail-created jails by
// jid string, but the verb-driven path needs an explicit name).
JailInfo createJail(const Spec &spec, const std::string &jailPath,
                    const std::string &jailName, bool logProgress);

// Remove a jail (race-free via descriptor if available)
void removeJail(const JailInfo &info);

// Apply RCTL resource limits (with verification), returns cleanup callback
RunAtEnd applyRctlLimits(const Spec &spec, int jid, bool logProgress);

// Diagnose cause of container death (OOM, signal, exit code)
std::string diagnoseExitReason(int jid, int exitStatus);

// Return true if the exit status indicates an OOM kill (for restart policies)
bool isOomKill(int exitStatus);

// Return true if the container was killed by an RCTL resource limit
bool wasKilledByRctl(int jid, int exitStatus);

// Return RCTL usage of a resource as a percentage of its limit (0-100),
// or -1 if no limit is set.  Enables memory pressure monitoring.
//
// 0.8.33: optional pre-fetched maps short-circuit the two `rctl(8)`
// fork+exec calls. `crate stats` passes its already-fetched maps;
// post-exit / single-resource callers pass nullptr and the function
// fetches via rctl(8) as before.
int getRctlUsagePercent(int jid, const std::string &resource,
                        const std::map<std::string, std::string> *prefetchedUsage = nullptr,
                        const std::map<std::string, std::string> *prefetchedLimits = nullptr);

// Apply ZFS disk quota (refquota) to container dataset
void applyDiskQuota(const Spec &spec, const std::string &jailPath, bool logProgress);

// Attach ZFS datasets to jail, returns cleanup callback
RunAtEnd attachZfsDatasets(const Spec &spec, int jid, bool logProgress);

// Create user, group, home directory inside jail
void createUserInJail(const Spec &spec, const std::string &jailPath, int jid,
                      const std::string &user, const std::string &homeDir,
                      uid_t uid, gid_t gid,
                      const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail,
                      const std::function<void(const char*)> &runScript,
                      bool logProgress);

}
