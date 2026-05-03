// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "backup_pure.h"

#include <ctime>
#include <cstdio>
#include <sstream>

namespace BackupPure {

std::string snapshotSuffix(long unixEpoch) {
  time_t t = (time_t)unixEpoch;
  std::tm tm{};
  ::gmtime_r(&t, &tm);
  char buf[40];
  std::strftime(buf, sizeof(buf), "backup-%Y-%m-%dT%H:%M:%SZ", &tm);
  return std::string(buf);
}

std::string fullSnapshotName(const std::string &dataset,
                             const std::string &suffix) {
  return dataset + "@" + suffix;
}

std::string streamFilename(const std::string &jailName,
                           const std::string &suffix,
                           const std::string &incFromSuffix) {
  if (incFromSuffix.empty())
    return jailName + "-" + suffix + ".zstream";
  return jailName + "-" + suffix + ".inc-from-" + incFromSuffix + ".zstream";
}

namespace {

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

bool hasShellMetachar(const std::string &s) {
  for (char c : s) {
    if (c == ';' || c == '`' || c == '$' || c == '|' || c == '&'
        || c == '<' || c == '>' || c == '\\' || c == '\n' || c == '\r'
        || c == '*' || c == '?' || c == '"' || c == '\'')
      return true;
  }
  return false;
}

bool hasDotDotSegment(const std::string &p) {
  size_t i = 0;
  while (i < p.size()) {
    auto slash = p.find('/', i);
    auto end = (slash == std::string::npos) ? p.size() : slash;
    if (p.substr(i, end - i) == "..") return true;
    if (slash == std::string::npos) break;
    i = slash + 1;
  }
  return false;
}

} // anon

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

std::string validateOutputDir(const std::string &dir) {
  if (dir.empty()) return "output directory is empty";
  if (dir.size() > 1024) return "output directory longer than 1024 chars";
  if (dir.front() != '/') return "output directory must be absolute";
  if (hasDotDotSegment(dir))
    return "output directory must not contain '..' segments";
  if (hasShellMetachar(dir))
    return "output directory contains shell metacharacters";
  return "";
}

std::string validateSinceName(const std::string &name) {
  if (name.empty()) return "--since value is empty";
  if (name.size() > 128) return "--since value longer than 128 chars";
  for (char c : name) {
    bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-'
                         || c == ':' || c == 'T' || c == '+';
    if (c == '@') return "--since must not contain '@'";
    if (c == '/') return "--since must not contain '/'";
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in --since value";
      return os.str();
    }
  }
  return "";
}

std::vector<std::string> buildSnapshotArgv(const std::string &dataset,
                                           const std::string &suffix) {
  return {"/sbin/zfs", "snapshot", dataset + "@" + suffix};
}

std::vector<std::string> buildSendArgv(const std::string &dataset,
                                       const std::string &currSuffix,
                                       const std::string &prevSuffix) {
  if (prevSuffix.empty())
    return {"/sbin/zfs", "send", dataset + "@" + currSuffix};
  return {"/sbin/zfs", "send", "-i",
          dataset + "@" + prevSuffix,
          dataset + "@" + currSuffix};
}

std::vector<std::string> buildRecvArgv(const std::string &destDataset) {
  return {"/sbin/zfs", "recv", destDataset};
}

std::vector<std::string> buildDestroySnapshotArgv(const std::string &dataset,
                                                  const std::string &suffix) {
  return {"/sbin/zfs", "destroy", dataset + "@" + suffix};
}

namespace {

bool parseUnsigned(const std::string &s, unsigned &out) {
  if (s.empty()) return false;
  unsigned long n = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    n = n * 10 + (unsigned)(c - '0');
    if (n > 0xFFFFFFFFul) return false;
  }
  out = (unsigned)n;
  return true;
}

} // anon

std::string parseRetention(const std::string &spec, RetentionPolicy &out) {
  if (spec.empty()) return "retention spec is empty";
  out = RetentionPolicy{};
  size_t i = 0;
  while (i < spec.size()) {
    auto comma = spec.find(',', i);
    auto end = (comma == std::string::npos) ? spec.size() : comma;
    auto pair = spec.substr(i, end - i);
    auto eq = pair.find('=');
    if (eq == std::string::npos)
      return "retention pair must be 'key=value', got '" + pair + "'";
    auto key = pair.substr(0, eq);
    auto val = pair.substr(eq + 1);
    unsigned n = 0;
    if (!parseUnsigned(val, n))
      return "retention value for '" + key + "' must be a non-negative integer";
    if (key == "hourly")       out.hourly = n;
    else if (key == "daily")   out.daily = n;
    else if (key == "weekly")  out.weekly = n;
    else if (key == "monthly") out.monthly = n;
    else
      return "unknown retention key '" + key + "' (allowed: hourly|daily|weekly|monthly)";
    if (comma == std::string::npos) break;
    i = comma + 1;
  }
  return "";
}

Plan choosePlan(const Inputs &in, bool autoIncremental) {
  Plan p;
  if (in.sinceProvided) {
    if (in.sinceName.empty()) {
      p.kind = Plan::Kind::Error;
      p.reason = "--since given but value is empty";
      return p;
    }
    p.kind = Plan::Kind::Incremental;
    p.sinceSuffix = in.sinceName;
    return p;
  }
  if (autoIncremental && in.priorBackupExists) {
    p.kind = Plan::Kind::Incremental;
    p.sinceSuffix = in.priorSnapshotSuffix;
    return p;
  }
  p.kind = Plan::Kind::Full;
  return p;
}

} // namespace BackupPure
