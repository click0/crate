// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "thin_jail_pure.h"

#include <algorithm>
#include <set>
#include <sstream>

namespace ThinJailPure {

const std::vector<std::string> &defaultHostDirs() {
  static const std::vector<std::string> dirs = {
    "/bin", "/sbin", "/lib", "/libexec", "/rescue",
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib32", "/usr/libexec",
    "/usr/libdata", "/usr/share", "/usr/include",
  };
  return dirs;
}

bool isOptionalHostDir(const std::string &dir) {
  return dir == "/usr/lib32" || dir == "/rescue" || dir == "/usr/include";
}

// Paths that belong to the writable layer; a host dir may be neither one
// of them nor live underneath one.
static const std::vector<std::string> &writableLayer() {
  static const std::vector<std::string> dirs = {
    "/etc", "/var", "/tmp", "/root", "/home", "/usr/local", "/usr/home",
    "/dev", "/proc", "/mnt", "/media",
  };
  return dirs;
}

static bool isOrUnder(const std::string &path, const std::string &prefix) {
  if (path == prefix) return true;
  return path.size() > prefix.size() && path.compare(0, prefix.size(), prefix) == 0
         && path[prefix.size()] == '/';
}

std::string validateHostDir(const std::string &dir) {
  if (dir.empty()) return "empty path";
  if (dir[0] != '/') return "'" + dir + "' is not an absolute path";
  if (dir == "/") return "'/' cannot be a host directory (mount the individual directories)";
  if (dir.size() > 1 && dir.back() == '/') return "'" + dir + "' has a trailing slash";
  if (dir.find_first_of("\t\n\r") != std::string::npos) return "'" + dir + "' contains control characters";
  // components
  size_t pos = 1;
  while (pos <= dir.size()) {
    size_t next = dir.find('/', pos);
    if (next == std::string::npos) next = dir.size();
    std::string comp = dir.substr(pos, next - pos);
    if (comp.empty()) return "'" + dir + "' has an empty path component";
    if (comp == "." || comp == "..") return "'" + dir + "' contains a '" + comp + "' component";
    pos = next + 1;
  }
  if (dir == "/usr")
    return "'/usr' would hide the jail's own /usr/local; list /usr/bin, /usr/lib, ... instead";
  for (auto &w : writableLayer())
    if (isOrUnder(dir, w))
      return "'" + dir + "' is part of the writable layer (" + w + ") and cannot come from the host";
  return "";
}

std::string validateHostDirs(const std::vector<std::string> &dirs) {
  if (dirs.empty()) return "the host directory list is empty";
  std::set<std::string> seen;
  for (auto &d : dirs) {
    if (auto e = validateHostDir(d); !e.empty()) return e;
    if (!seen.insert(d).second) return "'" + d + "' is listed twice";
  }
  for (auto &a : dirs)
    for (auto &b : dirs)
      if (a != b && isOrUnder(b, a))
        return "'" + b + "' lies inside '" + a + "' (the inner mount would be shadowed)";
  return "";
}

const std::vector<std::string> &baseArchiveSkeletonMembers() {
  static const std::vector<std::string> members = {"./etc", "./var", "./root", "./tmp"};
  return members;
}

std::vector<std::string> directoriesToCreate(const std::vector<std::string> &hostDirs) {
  std::vector<std::string> out = {"/dev", "/proc", "/media", "/mnt", "/home", "/usr", "/usr/local"};
  for (auto &d : hostDirs)
    if (std::find(out.begin(), out.end(), d) == out.end())
      out.push_back(d);
  return out;
}

std::vector<std::pair<std::string, std::string>>
mountPlan(const std::string &jailPath, const std::vector<std::string> &hostDirs) {
  std::vector<std::string> sorted = hostDirs;
  std::sort(sorted.begin(), sorted.end());
  std::vector<std::pair<std::string, std::string>> plan;
  for (auto &d : sorted)
    plan.emplace_back(jailPath + d, d);
  return plan;
}

// ---- manifest -------------------------------------------------------------

static const char *kHeader = "# crate thin jail v1";

std::string serializeManifest(const Manifest &m) {
  std::ostringstream os;
  os << kHeader << "\n";
  os << "mode\t" << m.mode << "\n";
  os << "osrelease\t" << m.osrelease << "\n";
  for (auto &d : m.hostDirs)
    os << "hostdir\t" << d << "\n";
  return os.str();
}

bool parseManifest(const std::string &content, Manifest &out, std::string &err) {
  out = Manifest{};
  out.mode.clear();
  if (content.size() > kManifestMaxBytes) { err = "manifest is too large"; return false; }
  std::istringstream is(content);
  std::string line;
  unsigned lineNo = 0;
  bool header = false;
  while (std::getline(is, line)) {
    ++lineNo;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    if (line[0] == '#') {
      if (lineNo == 1) header = (line == kHeader);
      continue;
    }
    auto tab = line.find('\t');
    if (tab == std::string::npos) { err = "line " + std::to_string(lineNo) + ": no tab separator"; return false; }
    std::string key = line.substr(0, tab), val = line.substr(tab + 1);
    if (val.empty()) { err = "line " + std::to_string(lineNo) + ": empty value for '" + key + "'"; return false; }
    if (key == "mode") {
      if (!out.mode.empty()) { err = "line " + std::to_string(lineNo) + ": duplicate mode"; return false; }
      if (val != "host-ro") { err = "unsupported thin jail mode '" + val + "'"; return false; }
      out.mode = val;
    } else if (key == "osrelease") {
      if (!out.osrelease.empty()) { err = "line " + std::to_string(lineNo) + ": duplicate osrelease"; return false; }
      if (val.find_first_of(" \t/") != std::string::npos) { err = "osrelease '" + val + "' is not a release string"; return false; }
      out.osrelease = val;
    } else if (key == "hostdir") {
      if (auto e = validateHostDir(val); !e.empty()) { err = "hostdir: " + e; return false; }
      out.hostDirs.push_back(val);
    } else {
      err = "line " + std::to_string(lineNo) + ": unknown key '" + key + "'";
      return false;
    }
  }
  if (!header) { err = "missing '# crate thin jail v1' header"; return false; }
  if (out.mode.empty()) { err = "missing mode"; return false; }
  if (out.osrelease.empty()) { err = "missing osrelease"; return false; }
  if (auto e = validateHostDirs(out.hostDirs); !e.empty()) { err = e; return false; }
  return true;
}

std::string majorMinor(const std::string &osrelease) {
  size_t i = 0;
  auto digits = [&](size_t &p) { size_t s = p; while (p < osrelease.size() && osrelease[p] >= '0' && osrelease[p] <= '9') ++p; return p > s; };
  if (!digits(i)) return "";
  if (i >= osrelease.size() || osrelease[i] != '.') return "";
  ++i;
  if (!digits(i)) return "";
  return osrelease.substr(0, i);
}

std::string releaseMismatchWarning(const std::string &created, const std::string &host) {
  auto c = majorMinor(created), h = majorMinor(host);
  if (c.empty() || h.empty() || c == h) return "";
  std::string majC = c.substr(0, c.find('.')), majH = h.substr(0, h.find('.'));
  std::string msg = "thin jail: the writable layer (/etc, /var) was extracted from FreeBSD " + created
                  + " but the host userland mounted into it is " + host + ".";
  if (majC != majH)
    msg += " Different major versions: rc.d scripts and /etc defaults may not drive these binaries;"
           " re-create the crate on this host (crate create) to refresh the writable layer.";
  else
    msg += " Minor versions differ; re-create the crate when something in /etc misbehaves.";
  return msg;
}

} // namespace ThinJailPure
