// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "warm_pure.h"

#include <ctime>
#include <sstream>

namespace WarmPure {

namespace {

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

} // anon

std::string validateTemplateDataset(const std::string &ds) {
  if (ds.empty()) return "template dataset is empty";
  if (ds.size() > 256) return "template dataset longer than 256 chars";
  if (ds.front() == '/' || ds.back() == '/')
    return "template dataset must not start or end with '/'";
  if (ds.find("//") != std::string::npos)
    return "template dataset must not contain empty path segments";
  for (char c : ds) {
    bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-' || c == '/';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in template dataset";
      return os.str();
    }
  }
  size_t i = 0;
  while (i < ds.size()) {
    auto slash = ds.find('/', i);
    auto end = (slash == std::string::npos) ? ds.size() : slash;
    auto seg = ds.substr(i, end - i);
    if (seg == "." || seg == "..")
      return "template dataset must not contain '.' or '..' segments";
    if (slash == std::string::npos) break;
    i = slash + 1;
  }
  return "";
}

std::string validateSnapshotSuffix(const std::string &suffix) {
  if (suffix.empty()) return "snapshot suffix is empty";
  if (suffix.size() > 64) return "snapshot suffix longer than 64 chars";
  for (char c : suffix) {
    bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-'
                         || c == ':' || c == 'T' || c == '+';
    if (c == '@') return "snapshot suffix must not contain '@'";
    if (c == '/') return "snapshot suffix must not contain '/'";
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in snapshot suffix";
      return os.str();
    }
  }
  return "";
}

std::string warmSnapshotSuffix(long unixEpoch) {
  time_t t = (time_t)unixEpoch;
  std::tm tm{};
  ::gmtime_r(&t, &tm);
  char buf[40];
  std::strftime(buf, sizeof(buf), "warm-%Y-%m-%dT%H:%M:%SZ", &tm);
  return std::string(buf);
}

std::string fullSnapshotName(const std::string &dataset,
                             const std::string &suffix) {
  return dataset + "@" + suffix;
}

std::vector<std::string> buildSnapshotArgv(const std::string &sourceDataset,
                                           const std::string &suffix) {
  return {"/sbin/zfs", "snapshot", sourceDataset + "@" + suffix};
}

std::vector<std::string> buildCloneArgv(const std::string &sourceDataset,
                                        const std::string &suffix,
                                        const std::string &templateDataset) {
  return {"/sbin/zfs", "clone",
          sourceDataset + "@" + suffix, templateDataset};
}

std::vector<std::string> buildPromoteArgv(const std::string &templateDataset) {
  return {"/sbin/zfs", "promote", templateDataset};
}

// --- Warm-base consumer side ---

std::string validateJailName(const std::string &name) {
  if (name.empty()) return "jail name is empty";
  if (name.size() > 64) return "jail name longer than 64 chars";
  if (name == "." || name == "..") return "jail name is reserved";
  for (char c : name) {
    bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in jail name";
      return os.str();
    }
  }
  return "";
}

std::string warmRunSnapshotSuffix(long unixEpoch) {
  time_t t = (time_t)unixEpoch;
  std::tm tm{};
  ::gmtime_r(&t, &tm);
  char buf[40];
  std::strftime(buf, sizeof(buf), "warmrun-%Y-%m-%dT%H:%M:%SZ", &tm);
  return std::string(buf);
}

std::string warmRunCloneName(const std::string &parentDataset,
                             const std::string &jailName,
                             const std::string &hex) {
  // Same naming convention as Locations::jailDirectoryPath::jail-<name>-<hex>.
  // Caller is responsible for having validated parentDataset (via
  // ZfsOps queries it sees on the host) and jailName (validateJailName).
  return parentDataset + "/jail-" + jailName + "-" + hex;
}

} // namespace WarmPure
