// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "mounts_pure.h"

#include <cctype>

namespace MountsPure {

bool splitRoSuffix(std::string &path) {
  auto ends = [&](const char *s) {
    std::string t(s);
    return path.size() > t.size() && path.compare(path.size() - t.size(), t.size(), t) == 0;
  };
  if (ends(":ro")) { path.erase(path.size() - 3); return true; }
  if (ends(":rw")) { path.erase(path.size() - 3); return false; }
  return false;
}

bool parseRoFlag(const std::string &flag, bool &readOnly, std::string &err) {
  if (flag == "ro") { readOnly = true;  return true; }
  if (flag == "rw") { readOnly = false; return true; }
  err = "the third element of a share must be 'ro' or 'rw', got '" + flag + "'";
  return false;
}

std::string validateTmpfsSize(const std::string &size) {
  if (size.empty()) return "";
  if (size.size() > 20) return "tmpfs size longer than 20 chars";
  size_t digits = 0;
  for (size_t i = 0; i < size.size(); i++) {
    char c = size[i];
    if (std::isdigit((unsigned char)c)) { digits++; continue; }
    if (i == size.size() - 1 && digits > 0 &&
        (c == 'k' || c == 'K' || c == 'm' || c == 'M' || c == 'g' || c == 'G'))
      continue;
    return "tmpfs size must be digits with an optional k/m/g suffix, got '" + size + "'";
  }
  if (digits == 0) return "tmpfs size has no digits";
  bool nonZero = false;
  for (char c : size) if (c >= '1' && c <= '9') { nonZero = true; break; }
  if (!nonZero) return "tmpfs size must be greater than zero";
  return "";
}

namespace {

std::vector<std::string> components(const std::string &path) {
  std::vector<std::string> out;
  std::string cur;
  for (size_t i = 1; i <= path.size(); i++) {
    if (i == path.size() || path[i] == '/') { out.push_back(cur); cur.clear(); }
    else cur += path[i];
  }
  return out;
}

} // anon

std::string validateTmpfsPath(const std::string &pathIn) {
  if (pathIn.empty()) return "tmpfs path is empty";
  std::string p = pathIn;
  if (p.compare(0, 5, "$HOME") == 0) {
    if (p.size() == 5) return "tmpfs on $HOME itself is not allowed (it would hide the home directory)";
    if (p[5] != '/') return "tmpfs path must start with '/' or '$HOME/'";
    p = p.substr(5);   // "/..." under the home: component checks below
  }
  if (p[0] != '/') return "tmpfs path must be absolute (or start with $HOME/): " + pathIn;
  if (p == "/") return "tmpfs on / is not allowed";
  if (p.back() == '/') return "tmpfs path must not end with '/': " + pathIn;
  for (const auto &c : components(p))
    if (c.empty() || c == "." || c == "..")
      return "tmpfs path must be normalised (no empty, '.' or '..' components): " + pathIn;
  if (pathIn.compare(0, 5, "$HOME") == 0) return "";
  static const char *forbidden[] = {"/dev", "/proc", "/etc", "/bin", "/sbin", "/lib", "/libexec",
                                    "/usr", "/usr/local", "/var/run", "/usr/local/etc"};
  for (const char *f : forbidden)
    if (p == f) return std::string("tmpfs on ") + f + " would hide the jail's own files";
  return "";
}

std::string validateEtcKeepName(const std::string &name) {
  if (name.empty()) return "etc/keep entry is empty";
  if (name.size() > 128) return "etc/keep entry longer than 128 chars";
  if (name == "." || name == "..") return "etc/keep entry '" + name + "' is not a file name";
  for (char c : name) {
    bool ok = std::isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-' || c == '+' || c == '@';
    if (!ok) return "etc/keep entry '" + name + "': only a plain name under /etc is allowed (letters, digits, . _ - + @)";
  }
  return "";
}

bool isUnder(const std::string &path, const std::string &dir) {
  if (dir.empty()) return false;
  if (dir == "/") return !path.empty() && path[0] == '/';
  return path == dir || (path.size() > dir.size() && path.compare(0, dir.size(), dir) == 0 && path[dir.size()] == '/');
}

std::vector<std::pair<std::string, std::string>>
tmpfsParams(const std::string &size, bool underHome, unsigned uid, unsigned gid) {
  std::vector<std::pair<std::string, std::string>> p;
  if (!size.empty()) p.emplace_back("size", size);
  if (underHome) {
    p.emplace_back("uid", std::to_string(uid));
    p.emplace_back("gid", std::to_string(gid));
    p.emplace_back("mode", "0700");
  } else {
    p.emplace_back("mode", "01777");
  }
  return p;
}

std::string validateDecimal(const std::string &s, const char *what) {
  if (s.empty()) return std::string(what) + " is empty";
  if (s.size() > 10) return std::string(what) + " longer than 10 digits";
  for (char c : s) if (!std::isdigit((unsigned char)c)) return std::string(what) + " must be decimal digits";
  return "";
}

std::string validateOctalMode(const std::string &mode) {
  if (mode.size() < 3 || mode.size() > 5) return "mode must be 3..5 octal digits";
  for (char c : mode) if (c < '0' || c > '7') return "mode must be octal digits";
  return "";
}

} // namespace MountsPure
