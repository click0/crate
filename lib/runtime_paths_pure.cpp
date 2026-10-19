// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "runtime_paths_pure.h"

#include <climits>
#include <string>

namespace RuntimePathsPure {

namespace {

constexpr const char *kLegacyRoot = "/var/run/crate";

std::string uidStr(uint32_t uid) {
  // Hand-rolled to avoid pulling <sstream> for a pure helper.
  if (uid == 0) return "0";
  std::string out;
  while (uid > 0) {
    out.insert(out.begin(), char('0' + (uid % 10)));
    uid /= 10;
  }
  return out;
}

} // anon

std::string legacyRoot() {
  return std::string(kLegacyRoot);
}

std::string perUserRoot(uint32_t uid) {
  return std::string(kLegacyRoot) + "/" + uidStr(uid);
}

std::string perUserLeasesDir(uint32_t uid) {
  return perUserRoot(uid) + "/leases";
}

std::string perUserLeaseFile(uint32_t uid, const std::string &jailName) {
  return perUserLeasesDir(uid) + "/" + jailName + ".lease";
}

std::string perUserExportsDir(uint32_t uid) {
  return perUserRoot(uid) + "/exports";
}

std::string perUserImportsDir(uint32_t uid) {
  return perUserRoot(uid) + "/imports";
}

std::string perUserCrateAuditLog(uint32_t uid) {
  return perUserRoot(uid) + "/crate-audit.log";
}

std::string perUserAuditLog(uint32_t uid) {
  return perUserRoot(uid) + "/audit.log";
}

namespace {
bool allDigits(const std::string &s) {
  if (s.empty()) return false;
  for (char c : s) if (c < '0' || c > '9') return false;
  return true;
}
} // anon

std::string crateJailDirName(const std::string &path) {
  const std::string root = std::string(kLegacyRoot) + "/";
  if (path.compare(0, root.size(), root) != 0) return "";
  std::string rest = path.substr(root.size());
  // optional "<uid>/" component
  auto slash = rest.find('/');
  if (slash != std::string::npos) {
    if (!allDigits(rest.substr(0, slash))) return "";
    rest = rest.substr(slash + 1);
    if (rest.find('/') != std::string::npos) return "";   // deeper: not a jail root
  }
  if (rest.compare(0, 5, "jail-") != 0 || rest.size() <= 5) return "";
  return rest;
}

bool isCrateJailPath(const std::string &path) {
  return !crateJailDirName(path).empty();
}

std::string validateUid(int64_t uid) {
  if (uid < 0) return "uid must be non-negative";
  if (uid > INT32_MAX) return "uid out of range (>INT32_MAX)";
  return "";
}

} // namespace RuntimePathsPure
