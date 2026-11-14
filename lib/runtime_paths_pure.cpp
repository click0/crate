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

std::string rootJailsRoot() {
  return perUserRoot(0);
}

unsigned runtimeRootMode(bool hasLegacyJailTrees) {
  return hasLegacyJailTrees ? 0700 : 0711;
}

bool isLegacyJailTreeName(const std::string &n) {
  auto starts = [&](const char *p) { return n.compare(0, std::string(p).size(), p) == 0; };
  static const std::string kCow = "-cow-writable";
  return starts("jail-") || starts("chroot-create-")
      || (n.size() > kCow.size() && n.compare(n.size() - kCow.size(), kCow.size(), kCow) == 0);
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

int64_t crateJailOwnerUid(const std::string &path) {
  if (crateJailDirName(path).empty()) return -1;
  const std::string rest = path.substr(std::string(kLegacyRoot).size() + 1);
  auto slash = rest.find('/');
  if (slash == std::string::npos) return 0;   // legacy: root's
  const std::string uid = rest.substr(0, slash);
  if (uid.size() > 10) return -1;
  int64_t v = std::stoll(uid);
  return v > INT32_MAX ? -1 : v;
}

std::string crateJailRootOf(const std::string &path) {
  const std::string root = std::string(kLegacyRoot) + "/";
  if (path.compare(0, root.size(), root) != 0) return "";
  // the jail directory is the first or, after "<uid>/", the second component
  size_t start = root.size();
  for (int i = 0; i < 2; i++) {
    size_t end = path.find('/', start);
    if (end == std::string::npos) end = path.size();
    const std::string candidate = path.substr(0, end);
    if (isCrateJailPath(candidate)) return candidate;
    if (end >= path.size()) break;
    start = end + 1;
  }
  return "";
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
