// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "passwd_pure.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace PasswdPure {

namespace {

std::vector<std::string> splitColons(const std::string &line) {
  std::vector<std::string> f;
  std::string cur;
  for (char c : line) {
    if (c == ':') { f.push_back(cur); cur.clear(); }
    else cur.push_back(c);
  }
  f.push_back(cur);
  return f;
}

bool parseId(const std::string &s, uint32_t &out) {
  if (s.empty() || s.size() > 10) return false;
  uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + (uint64_t)(c - '0');
  }
  if (v > 0xFFFFFFFFull) return false;
  out = (uint32_t)v;
  return true;
}

bool parseEither(const std::string &line, User &out) {
  if (line.empty() || line[0] == '#') return false;
  auto f = splitColons(line);
  if (f.size() == 10) {               // master.passwd(5)
    if (f[0].empty()) return false;
    User u;
    u.name = f[0];
    if (!parseId(f[2], u.uid) || !parseId(f[3], u.gid)) return false;
    u.loginClass = f[4];
    u.home = f[8];
    u.shell = f[9];
    out = std::move(u);
    return true;
  }
  if (f.size() == 7) {                // passwd(5)
    if (f[0].empty()) return false;
    User u;
    u.name = f[0];
    if (!parseId(f[2], u.uid) || !parseId(f[3], u.gid)) return false;
    u.home = f[5];
    u.shell = f[6];
    out = std::move(u);
    return true;
  }
  return false;
}

} // anon

bool parseMasterPasswdLine(const std::string &line, User &out) {
  if (line.empty() || line[0] == '#') return false;
  if (splitColons(line).size() != 10) return false;
  return parseEither(line, out);
}

bool lookupUser(const std::string &content, const std::string &name, User &out) {
  if (name.empty()) return false;
  std::istringstream in(content);
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    User u;
    if (!parseEither(line, u)) continue;
    if (u.name == name) { out = std::move(u); return true; }
  }
  return false;
}

std::vector<uint32_t> supplementaryGroups(const std::string &content,
                                          const std::string &user,
                                          uint32_t primaryGid,
                                          size_t maxGroups) {
  std::vector<uint32_t> groups{primaryGid};
  if (user.empty() || maxGroups <= 1) return groups;
  std::istringstream in(content);
  std::string line;
  while (std::getline(in, line) && groups.size() < maxGroups) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    auto f = splitColons(line);
    if (f.size() != 4) continue;
    uint32_t gid;
    if (!parseId(f[2], gid)) continue;
    bool member = false;
    std::string m;
    std::istringstream members(f[3]);
    while (std::getline(members, m, ',')) {
      if (m == user) { member = true; break; }
    }
    if (!member) continue;
    if (std::find(groups.begin(), groups.end(), gid) == groups.end())
      groups.push_back(gid);
  }
  return groups;
}

namespace {

bool allOf(const std::string &s, const char *extra) {
  for (char c : s) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                    (c != '\0' && std::strchr(extra, c) != nullptr);
    if (!ok) return false;
  }
  return true;
}

bool displayOk(const std::string &v)  { return v.size() <= 64 && allOf(v, ".:_-"); }
bool wlNameOk(const std::string &v)   { return v.size() <= 64 && allOf(v, "._-") && v != "." && v != ".."; }
bool jailPathOk(const std::string &v) {
  if (v.empty() || v[0] != '/' || v.size() > 255 || !allOf(v, "/._+-")) return false;
  // no ".." component
  size_t i = 0;
  while (i < v.size()) {
    const size_t j = v.find('/', i);
    const std::string comp = v.substr(i, j == std::string::npos ? std::string::npos : j - i);
    if (comp == "..") return false;
    if (j == std::string::npos) break;
    i = j + 1;
  }
  return true;
}

}

std::string *jailDisplayField(JailDisplayEnv &d, const std::string &name) {
  if (name == "DISPLAY") return &d.display;
  if (name == "XAUTHORITY") return &d.xauthority;
  if (name == "WAYLAND_DISPLAY") return &d.waylandDisplay;
  if (name == "XDG_RUNTIME_DIR") return &d.xdgRuntimeDir;
  return nullptr;
}

std::string validateJailDisplayEnv(const JailDisplayEnv &d) {
  if (!d.display.empty() && !displayOk(d.display))
    return "display: up to 64 characters of [A-Za-z0-9.:_-]";
  if (!d.waylandDisplay.empty() && !wlNameOk(d.waylandDisplay))
    return "wayland_display: a socket name, up to 64 characters of [A-Za-z0-9._-]";
  if (!d.xauthority.empty() && !jailPathOk(d.xauthority))
    return "xauthority: an absolute path of [A-Za-z0-9/._+-] without '..'";
  if (!d.xdgRuntimeDir.empty() && !jailPathOk(d.xdgRuntimeDir))
    return "xdg_runtime_dir: an absolute path of [A-Za-z0-9/._+-] without '..'";
  return "";
}

bool validLocaleName(const std::string &lang) {
  return !lang.empty() && lang.size() <= 64 && allOf(lang, "_.@-");
}

std::vector<std::string> jailExecEnv(const std::string &user, const std::string &home,
                                     const std::string &shell, const std::string &term,
                                     const std::string &lang, const JailDisplayEnv &display) {
  std::vector<std::string> env = {
    "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
    "HOME=" + (home.empty() ? std::string("/") : home),
    "SHELL=" + (shell.empty() ? std::string("/bin/sh") : shell),
    "USER=" + user,
    "LOGNAME=" + user,
  };
  if (!term.empty()) env.push_back("TERM=" + term);
  if (validLocaleName(lang)) env.push_back("LANG=" + lang);
  // 1.1.78
  if (!display.display.empty() && displayOk(display.display))
    env.push_back("DISPLAY=" + display.display);
  if (!display.xauthority.empty() && jailPathOk(display.xauthority))
    env.push_back("XAUTHORITY=" + display.xauthority);
  if (!display.waylandDisplay.empty() && wlNameOk(display.waylandDisplay))
    env.push_back("WAYLAND_DISPLAY=" + display.waylandDisplay);
  if (!display.xdgRuntimeDir.empty() && jailPathOk(display.xdgRuntimeDir))
    env.push_back("XDG_RUNTIME_DIR=" + display.xdgRuntimeDir);
  return env;
}

}
