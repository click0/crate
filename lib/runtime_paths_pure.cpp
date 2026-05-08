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

std::string perUserAuditLog(uint32_t uid) {
  return perUserRoot(uid) + "/audit.log";
}

std::string validateUid(int64_t uid) {
  if (uid < 0) return "uid must be non-negative";
  if (uid > INT32_MAX) return "uid out of range (>INT32_MAX)";
  return "";
}

} // namespace RuntimePathsPure
