// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// MAC framework: ugidfw via /dev/ugidfw ioctl, portacl via sysctl.

#include "mac_ops.h"
#include "mac_pure.h"     // 1.1.44: portacl list merge/remove
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <sys/ioctl.h>
#include <sys/sysctl.h>
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

// Native ugidfw ioctl path is not available on stock FreeBSD —
// mac_bsdextended uses sysctl, not /dev/ugidfw ioctls.
// Always fall through to the ugidfw(8) command fallback.
static bool nativeAddRule(const UgidfwRule &) { return false; }

static bool nativeRemoveRule(int) { return false; }

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

  // 1.1.44: ugidfw(8) parses per argv — one token per word, not the
  // whole rule as a single argument (which it rejected).
  auto words = Util::splitString(ss.str(), " ");
  std::vector<std::string> argv{CRATE_PATH_UGIDFW};
  argv.insert(argv.end(), words.begin(), words.end());
  Util::execCommand(argv, "add ugidfw rule");
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

static std::vector<std::string> portaclTokens(const std::vector<PortaclRule> &rules) {
  std::vector<std::string> out;
  for (const auto &r : rules)
    out.push_back(MacPure::formatPortaclRule(r.uid, r.proto, r.port));
  return out;
}

static void writePortaclRules(const std::string &rulesStr) {
  Util::setSysctlInt("security.mac.portacl.suser_exempt", 1);
  if (::sysctlbyname("security.mac.portacl.rules", nullptr, nullptr,
                      rulesStr.c_str(), rulesStr.size()) != 0) {
    // Fallback: sysctl command
    Util::execCommand({CRATE_PATH_SYSCTL, STR("security.mac.portacl.rules=" << rulesStr)},
      "set portacl rules");
  }
}

void setPortaclRules(const std::vector<PortaclRule> &rules) {
  std::string joined;
  for (const auto &t : portaclTokens(rules)) {
    if (!joined.empty()) joined += ',';
    joined += t;
  }
  writePortaclRules(joined);
}

void addPortaclRules(const std::vector<PortaclRule> &rules) {
  std::string current;
  try { current = Util::getSysctlString("security.mac.portacl.rules"); } catch (...) {}
  writePortaclRules(MacPure::mergePortaclRules(current, portaclTokens(rules)));
}

void removePortaclRules(const std::vector<PortaclRule> &rules) {
  std::string current;
  try { current = Util::getSysctlString("security.mac.portacl.rules"); } catch (...) {}
  writePortaclRules(MacPure::removePortaclRules(current, portaclTokens(rules)));
}

}
