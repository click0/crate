// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// MAC framework: ugidfw via /dev/ugidfw ioctl, portacl via sysctl.

#include "mac_ops.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <security/mac_bsdextended/mac_bsdextended.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <sstream>

#define ERR(msg...) ERR2("mac", msg)

namespace MacOps {

// --- /dev/ugidfw ioctl-based access ---

static const char *UGIDFW_DEV = "/dev/ugidfw";

// --- Runtime detection: native ioctl vs shell ugidfw(8) ---

static bool g_ugidfwDetected = false;
static bool g_ugidfwNative = false;

// Check whether /dev/ugidfw is accessible for read+write.
// If the device node exists and is accessible, the native ioctl path
// will be used; otherwise all operations fall back to ugidfw(8).
// Result is probed once and cached for the process lifetime.
bool useNativeUgidfw() {
  if (!g_ugidfwDetected) {
    g_ugidfwDetected = true;
    g_ugidfwNative = (::access(UGIDFW_DEV, R_OK | W_OK) == 0);
  }
  return g_ugidfwNative;
}

// RAII wrapper for /dev/ugidfw file descriptor
class UgidfwDev {
public:
  UgidfwDev() : fd_(::open(UGIDFW_DEV, O_RDWR)) {}
  ~UgidfwDev() { if (fd_ >= 0) ::close(fd_); }
  int fd() const { return fd_; }
  bool valid() const { return fd_ >= 0; }
private:
  int fd_;
};

// Try native ioctl, return true on success
static bool nativeAddRule(const UgidfwRule &rule) {
  if (!useNativeUgidfw())
    return false;

  UgidfwDev dev;
  if (!dev.valid())
    return false;

  struct mac_bsdextended_rule mbr;
  memset(&mbr, 0, sizeof(mbr));

  // Subject: jail ID
  if (rule.jailJid >= 0) {
    mbr.mbr_subject.mbs_flags |= MBS_PRISON_DEFINED;
    mbr.mbr_subject.mbs_prison = rule.jailJid;
  }

  // Subject: UID
  if (rule.subjectUid >= 0) {
    mbr.mbr_subject.mbs_flags |= MBS_UID_DEFINED;
    mbr.mbr_subject.mbs_uid_min = rule.subjectUid;
    mbr.mbr_subject.mbs_uid_max = rule.subjectUid;
  }

  // Object: UID
  if (rule.objectUid >= 0) {
    mbr.mbr_object.mbo_flags |= MBO_UID_DEFINED;
    mbr.mbr_object.mbo_uid_min = rule.objectUid;
    mbr.mbr_object.mbo_uid_max = rule.objectUid;
  }

  // Object: filesystem path
  if (!rule.objectPath.empty()) {
    mbr.mbr_object.mbo_flags |= MBO_FSID_DEFINED;
    // Resolve fsid from path via statfs
    struct statfs sfs;
    if (::statfs(rule.objectPath.c_str(), &sfs) == 0) {
      mbr.mbr_object.mbo_fsid = sfs.f_fsid;
    }
  }

  // Mode: convert bitmask to mac_bsdextended mode flags
  mbr.mbr_mode = 0;
  if (!(rule.mode & 4)) mbr.mbr_mode |= MBI_READ;
  if (!(rule.mode & 2)) mbr.mbr_mode |= MBI_WRITE;
  if (!(rule.mode & 1)) mbr.mbr_mode |= MBI_EXEC;

  // Get current rule count to determine next slot
  int ruleCount = 0;
  size_t len = sizeof(ruleCount);
  ::sysctlbyname("security.mac.bsdextended.rule_count", &ruleCount, &len, nullptr, 0);

  // Use ioctl to add rule at the next available slot
  struct {
    int slot;
    struct mac_bsdextended_rule rule;
  } iocReq;
  iocReq.slot = ruleCount;
  iocReq.rule = mbr;

  if (::ioctl(dev.fd(), MAC_BSDEXTENDED_ADD_RULE, &iocReq) == 0)
    return true;

  return false;
}

static bool nativeRemoveRule(int slot) {
  if (!useNativeUgidfw())
    return false;

  UgidfwDev dev;
  if (!dev.valid())
    return false;

  return ::ioctl(dev.fd(), MAC_BSDEXTENDED_REMOVE_RULE, &slot) == 0;
}

// --- Public API ---

void addUgidfwRule(const UgidfwRule &rule) {
  // Try native ioctl first (only if /dev/ugidfw is accessible)
  if (nativeAddRule(rule))
    return;

  // Fallback to ugidfw(8) command
  std::ostringstream ss;
  ss << "add";
  if (rule.jailJid >= 0)
    ss << " subject jailid " << rule.jailJid;
  if (rule.subjectUid >= 0)
    ss << " subject uid " << rule.subjectUid;
  if (rule.objectUid >= 0)
    ss << " object uid " << rule.objectUid;
  if (!rule.objectPath.empty())
    ss << " object filesys " << rule.objectPath;
  ss << " mode ";
  if (rule.mode == 0)
    ss << "n";
  else {
    if (rule.mode & 4) ss << "r";
    if (rule.mode & 2) ss << "w";
    if (rule.mode & 1) ss << "x";
  }

  Util::execCommand({CRATE_PATH_UGIDFW, ss.str()}, "add ugidfw rule");
}

void addUgidfwRuleRaw(const std::string &ruleStr) {
  auto ruleArgs = Util::splitString(ruleStr, " ");
  auto fullArgs = std::vector<std::string>{CRATE_PATH_UGIDFW, "add"};
  fullArgs.insert(fullArgs.end(), ruleArgs.begin(), ruleArgs.end());
  Util::execCommand(fullArgs, STR("add ugidfw rule: " << ruleStr));
}

void removeUgidfwRules(int jailJid) {
  std::vector<std::string> rules;
  listUgidfwRules(rules);

  auto jidStr = std::to_string(jailJid);
  for (size_t i = rules.size(); i > 0; i--) {
    auto &r = rules[i - 1];
    if (r.find(STR("jailid " << jidStr)) != std::string::npos) {
      // Try native ioctl first (only if /dev/ugidfw is accessible)
      if (nativeRemoveRule((int)(i - 1)))
        continue;
      // Fallback
      try {
        Util::execCommand({CRATE_PATH_UGIDFW, "remove", std::to_string(i - 1)},
          "remove ugidfw rule");
      } catch (...) {}
    }
  }
}

void listUgidfwRules(std::vector<std::string> &output) {
  try {
    auto result = Util::execCommandGetOutput({CRATE_PATH_UGIDFW, "list"}, "list ugidfw rules");
    std::istringstream is(result);
    std::string line;
    while (std::getline(is, line))
      if (!line.empty())
        output.push_back(line);
  } catch (...) {}
}

void setPortaclRules(const std::vector<PortaclRule> &rules) {
  std::ostringstream ss;
  for (size_t i = 0; i < rules.size(); i++) {
    if (i > 0) ss << ",";
    ss << "uid:" << rules[i].uid << ":" << rules[i].proto << ":" << rules[i].port;
  }
  auto rulesStr = ss.str();
  Util::setSysctlInt("security.mac.portacl.suser_exempt", 1);

  auto value = rulesStr;
  if (::sysctlbyname("security.mac.portacl.rules", nullptr, nullptr,
                      value.c_str(), value.size()) != 0) {
    // Fallback: sysctl command
    Util::execCommand({CRATE_PATH_SYSCTL, STR("security.mac.portacl.rules=" << rulesStr)},
      "set portacl rules");
  }
}

}
