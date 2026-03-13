// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "run_jail.h"
#include "spec.h"
#include "zfs_ops.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

// sys/jail.h isn't C++-safe: https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=238928
extern "C" {
#include <sys/jail.h>
}
#include <jail.h>
#include <pwd.h>
#include <sys/stat.h>

#include <iostream>
#include <string>
#include <filesystem>
#include <limits>

#define ERR(msg...) ERR2("jail", msg)
#define WARN(msg...) \
  std::cerr << rang::fg::yellow << msg << rang::style::reset << std::endl;

namespace RunJail {

JailInfo createJail(const Spec &spec, const std::string &jailPath, bool logProgress) {
  const char *optNet = spec.optionExists("net") ? "true" : "false";
  const char *optRawSockets = spec.ipcRawSocketsOverride
    ? (spec.ipcRawSocketsValue ? "true" : "false")
    : optNet;
  const char *optSysvipc = spec.allowSysvipc ? "true" : "false";
  const bool hasZfsDatasets = !spec.zfsDatasets.empty();
  const char *optZfsMount = hasZfsDatasets ? "true" : "false";

  const char *optEnforceStatfs;
  if (spec.enforceStatfs >= 0)
    optEnforceStatfs = spec.enforceStatfs == 0 ? "0" : (spec.enforceStatfs == 1 ? "1" : "2");
  else
    optEnforceStatfs = hasZfsDatasets ? "1" : "2";

  const char *optAllowQuotas = spec.allowQuotas ? "true" : "false";
  const char *optSetHostname = spec.allowSetHostname ? "true" : "false";
  const char *optAllowChflags = spec.allowChflags ? "true" : "false";
  const char *optAllowMlock = spec.allowMlock ? "true" : "false";

  JailInfo info = {-1, -1};
  int res;

#ifdef JAIL_OWN_DESC
  if (Util::getFreeBSDMajorVersion() >= 15) {
    char descBuf[32] = {0};
    res = ::jail_setv(JAIL_CREATE | JAIL_OWN_DESC,
      "path", jailPath.c_str(),
      "host.hostname", Util::gethostname().c_str(),
      "persist", nullptr,
      "allow.raw_sockets", optRawSockets,
      "allow.socket_af", optNet,
      "allow.sysvipc", optSysvipc,
      "allow.mount", optZfsMount,
      "allow.mount.zfs", optZfsMount,
      "allow.quotas", optAllowQuotas,
      "allow.set_hostname", optSetHostname,
      "allow.chflags", optAllowChflags,
      "allow.mlock", optAllowMlock,
      "enforce_statfs", optEnforceStatfs,
      "vnet", nullptr,
      "desc", descBuf,
      nullptr);
    if (res == -1)
      ERR("failed to create jail: " << jail_errmsg)
    info.jid = res;
    info.jailFd = std::atoi(descBuf);
    if (logProgress)
      std::cerr << rang::fg::gray << "jail descriptor fd=" << info.jailFd << rang::style::reset << std::endl;
  } else
#endif
  {
    res = ::jail_setv(JAIL_CREATE,
      "path", jailPath.c_str(),
      "host.hostname", Util::gethostname().c_str(),
      "persist", nullptr,
      "allow.raw_sockets", optRawSockets,
      "allow.socket_af", optNet,
      "allow.sysvipc", optSysvipc,
      "allow.mount", optZfsMount,
      "allow.mount.zfs", optZfsMount,
      "allow.quotas", optAllowQuotas,
      "allow.set_hostname", optSetHostname,
      "allow.chflags", optAllowChflags,
      "allow.mlock", optAllowMlock,
      "enforce_statfs", optEnforceStatfs,
      "vnet", nullptr,
      nullptr);
    if (res == -1)
      ERR("failed to create jail: " << jail_errmsg)
    info.jid = res;
  }

  return info;
}

void removeJail(const JailInfo &info) {
#ifdef JAIL_OWN_DESC
  if (info.jailFd >= 0) {
    if (::jail_remove_jd(info.jailFd) == -1)
      ERR("failed to remove jail: " << strerror(errno))
    ::close(info.jailFd);
    return;
  }
#endif
  if (::jail_remove(info.jid) == -1)
    ERR("failed to remove jail: " << strerror(errno))
}

RunAtEnd applyRctlLimits(const Spec &spec, int jid, bool logProgress) {
  if (spec.limits.empty())
    return RunAtEnd();

  auto jidStr = std::to_string(jid);
  for (auto &lim : spec.limits) {
    auto rule = STR("jail:" << jidStr << ":" << lim.first << ":deny=" << lim.second);
    if (logProgress)
      std::cerr << rang::fg::gray << "applying RCTL rule: " << rule << rang::style::reset << std::endl;
    Util::execCommand({CRATE_PATH_RCTL, "-a", rule}, CSTR("apply RCTL rule " << lim.first));
  }

  // Verify that RCTL rules were actually applied
  try {
    auto listing = Util::execCommandGetOutput(
      {CRATE_PATH_RCTL, "-l", STR("jail:" << jidStr)}, "verify RCTL rules");
    for (auto &lim : spec.limits) {
      if (listing.find(lim.first) == std::string::npos)
        WARN("RCTL limit '" << lim.first << "' may not be enforced — "
             "check that kern.racct.enable=1 is set in /boot/loader.conf")
    }
  } catch (...) {
    WARN("cannot verify RCTL rules — check kern.racct.enable=1 in /boot/loader.conf")
  }

  return RunAtEnd([jid, logProgress]() {
    auto jidStr = std::to_string(jid);
    if (logProgress)
      std::cerr << rang::fg::gray << "removing RCTL rules for jail " << jidStr << rang::style::reset << std::endl;
    Util::execCommand({CRATE_PATH_RCTL, "-r", STR("jail:" << jidStr)}, "remove RCTL rules");
  });
}

// Diagnose the cause of container death based on exit status and RCTL state.
// Returns a human-readable reason string.
std::string diagnoseExitReason(int jid, int exitStatus) {
  auto jidStr = std::to_string(jid);

  // SIGKILL (signal 9) with exit status 137 typically indicates OOM
  if (WIFSIGNALED(exitStatus) && WTERMSIG(exitStatus) == SIGKILL) {
    // Check RCTL usage to determine if it was memory-related
    try {
      auto usage = Util::execCommandGetOutput(
        {CRATE_PATH_RCTL, "-u", STR("jail:" << jidStr)}, "check RCTL usage");

      // Look for memory limits that were hit
      for (auto &resource : {"memoryuse", "vmemoryuse", "swapuse"}) {
        auto pos = usage.find(resource);
        if (pos != std::string::npos) {
          auto valueStart = usage.find('=', pos);
          if (valueStart != std::string::npos) {
            auto valueEnd = usage.find('\n', valueStart);
            auto value = usage.substr(valueStart + 1,
                                       valueEnd - valueStart - 1);
            return STR("OOM: killed by RCTL (" << resource << "=" << value << ")");
          }
        }
      }
    } catch (...) {}

    return "killed by signal SIGKILL (possible OOM)";
  }

  if (WIFSIGNALED(exitStatus))
    return STR("killed by signal " << WTERMSIG(exitStatus));

  if (WIFEXITED(exitStatus) && WEXITSTATUS(exitStatus) != 0)
    return STR("exited with code " << WEXITSTATUS(exitStatus));

  return "exited normally";
}

// Apply ZFS disk quota (refquota) to the container's dataset
void applyDiskQuota(const Spec &spec, const std::string &jailPath, bool logProgress) {
  if (spec.diskQuota.empty())
    return;

  // Determine the ZFS dataset for the jail path
  if (!Util::Fs::isOnZfs(jailPath)) {
    WARN("disk_quota specified but jail path is not on ZFS — ignoring")
    return;
  }

  auto dataset = Util::Fs::getZfsDataset(jailPath);
  if (dataset.empty()) {
    WARN("disk_quota specified but could not determine ZFS dataset — ignoring")
    return;
  }

  if (logProgress)
    std::cerr << rang::fg::gray << "setting ZFS refquota " << spec.diskQuota
              << " on " << dataset << rang::style::reset << std::endl;

  ZfsOps::setRefquota(dataset, spec.diskQuota);
}

RunAtEnd attachZfsDatasets(const Spec &spec, int jid, bool logProgress) {
  if (spec.zfsDatasets.empty())
    return RunAtEnd();

  for (auto &dataset : spec.zfsDatasets) {
    if (logProgress)
      std::cerr << rang::fg::gray << "attaching ZFS dataset " << dataset << " to jail " << jid << rang::style::reset << std::endl;
    ZfsOps::jailDataset(jid, dataset);
  }

  return RunAtEnd([&spec, jid, logProgress]() {
    for (auto &dataset : Util::reverseVector(spec.zfsDatasets)) {
      if (logProgress)
        std::cerr << rang::fg::gray << "detaching ZFS dataset " << dataset << " from jail " << jid << rang::style::reset << std::endl;
      ZfsOps::unjailDataset(jid, dataset);
    }
  });
}

void createUserInJail(const Spec &spec, const std::string &jailPath, int jid,
                      const std::string &user, const std::string &homeDir,
                      uid_t uid, gid_t gid,
                      const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail,
                      const std::function<void(const char*)> &runScript,
                      bool logProgress) {
  auto J = [&jailPath](auto subdir) {
    return STR(jailPath << subdir);
  };

  if (logProgress)
    std::cerr << rang::fg::gray << "create user's home directory " << homeDir << ", uid=" << uid << " gid=" << gid << rang::style::reset << std::endl;

  Util::Fs::mkdir(J("/home"), 0755);
  Util::Fs::mkdir(J(homeDir), 0755);
  Util::Fs::chown(J(homeDir), uid, gid);

  runScript("run:before-create-users");

  if (logProgress)
    std::cerr << rang::fg::gray << "add group " << user << " in jail" << rang::style::reset << std::endl;
  execInJail({"/usr/sbin/pw", "groupadd", user, "-g", std::to_string(gid)}, "add the group in jail");

  if (logProgress)
    std::cerr << rang::fg::gray << "add user " << user << " in jail" << rang::style::reset << std::endl;
  execInJail({"/usr/sbin/pw", "useradd", user, "-u", std::to_string(uid), "-g", std::to_string(gid),
              "-s", "/bin/sh", "-d", homeDir}, "add the user in jail");
  execInJail({"/usr/sbin/pw", "usermod", user, "-G", "wheel"}, "add the group to the user");

  if (logProgress)
    std::cerr << rang::fg::gray << "verify user " << user << " group membership" << rang::style::reset << std::endl;
  execInJail({"/usr/bin/id", user}, "verify user group membership");

  // "video" option requires the corresponding user/group
  if (spec.optionExists("video")) {
    static const char *devName = "/dev/video";
    static unsigned devNameLen = ::strlen(devName);
    uid_t videoUid = std::numeric_limits<uid_t>::max();
    gid_t videoGid = std::numeric_limits<gid_t>::max();
    for (const auto &entry : std::filesystem::directory_iterator("/dev")) {
      auto cpath = entry.path().native();
      if (cpath.size() >= devNameLen+1 && cpath.substr(0, devNameLen) == devName && ::isdigit(cpath[devNameLen])) {
        struct stat sb;
        if (::stat(cpath.c_str(), &sb) != 0)
          ERR("can't stat the video device '" << cpath << "'");
        if (videoUid == std::numeric_limits<uid_t>::max()) {
          videoUid = sb.st_uid;
          videoGid = sb.st_gid;
        } else if (sb.st_uid != videoUid || sb.st_gid != videoGid) {
          WARN("video devices have different uid/gid combinations")
        }
      }
    }

    if (videoUid != std::numeric_limits<uid_t>::max()) {
      execInJail({"/usr/sbin/pw", "groupadd", "videoops", "-g", std::to_string(videoGid)}, "add the videoops group");
      execInJail({"/usr/sbin/pw", "groupmod", "videoops", "-m", user}, "add the main user to the videoops group");
      execInJail({"/usr/sbin/pw", "useradd", "video", "-u", std::to_string(videoUid),
                  "-g", std::to_string(videoGid)}, "add the video user in jail");
    } else {
      WARN("the app expects video, but no video devices are present")
    }
  }

  runScript("run:after-create-users");
}

}
