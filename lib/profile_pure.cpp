// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "profile_pure.h"
#include "warm_pure.h"

namespace ProfilePure {

static const char kLocalSuffix[] = ".local";

std::string validateProfileName(const std::string &name) {
  if (auto e = WarmPure::validateJailName(name); !e.empty())
    return "profile name '" + name + "': " + e
           + " (the profile name becomes the jail name; allowed: [A-Za-z0-9._-])";
  // the name is a CLI word and a file stem: no option look-alikes, no
  // hidden files, no "."/".."
  if (name[0] == '-' || name[0] == '.')
    return "profile name '" + name + "' must not start with '-' or '.'";
  const std::string suffix = kLocalSuffix;
  if (name.size() > suffix.size()
      && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0)
    return "profile name '" + name + "' must not end in '.local' (reserved for the "
           "<name>.local.yml override)";
  return "";
}

std::vector<std::string> specSearchPaths(const std::string &home, const std::string &name) {
  return {
    home + "/.config/crate/profiles/" + name + ".yml",
    "/usr/local/share/crate/profiles/" + name + ".yml",
    "/usr/local/share/examples/crate/" + name + ".yml",
  };
}

std::string localOverridePath(const std::string &home, const std::string &name) {
  return home + "/.config/crate/profiles/" + name + ".local.yml";
}

std::string buildDir(const std::string &home) {
  return home + "/.local/share/crate/profiles";
}

std::string cratePath(const std::string &home, const std::string &name) {
  return buildDir(home) + "/" + name + ".crate";
}

std::string mergedSpecPath(const std::string &home, const std::string &name) {
  return buildDir(home) + "/" + name + ".yml";
}

const std::vector<std::string> &forbiddenLocalKeys() {
  static const std::vector<std::string> keys = {
    "security_advanced",   // MAC / capsicum / sysctl hardening chosen by the profile
    "dbus",                // D-Bus policy: a filter is only as strict as its loosest rule
    "base",                // host-ro / host-dirs: mounts host directories into the jail
    "scripts",             // shell run as root in the create chroot and at run time
    "encrypted",           // turning encryption off or weakening the cipher
    "securelevel",         // lowering it
    "socket_proxy",        // exposes host unix sockets (same class as shares outside $HOME)
  };
  return keys;
}

std::string checkLocalTopLevelKey(const std::string &key) {
  for (auto &k : forbiddenLocalKeys())
    if (k == key)
      return "a .local override may not set '" + key + "' (it could loosen the profile's "
             "isolation); put it in a copy of the profile under ~/.config/crate/profiles/ instead";
  return "";
}

static bool hasDotDotComponent(const std::string &p) {
  size_t i = 0;
  while (i <= p.size()) {
    size_t j = p.find('/', i);
    if (j == std::string::npos) j = p.size();
    if (j - i == 2 && p[i] == '.' && p[i + 1] == '.') return true;
    i = j + 1;
  }
  return false;
}

std::string checkLocalShareHostPath(const std::string &hostPath, const std::string &home) {
  if (hostPath.empty()) return "share host path is empty";
  for (char c : hostPath)
    if ((unsigned char)c < 0x20 || c == 0x7f)
      return "share host path contains a control character";
  if (hasDotDotComponent(hostPath))
    return "share host path '" + hostPath + "' contains '..'";
  if (hostPath[0] == '~')
    return "share host path '" + hostPath + "': crate does not expand '~', write $HOME";

  // crate's own variable: "$HOME" or "$HOME/..."
  if (hostPath.compare(0, 5, "$HOME") == 0 && (hostPath.size() == 5 || hostPath[5] == '/'))
    return "";
  if (hostPath[0] == '$')
    return "share host path '" + hostPath + "': only $HOME is substituted";
  if (hostPath[0] != '/')
    return "share host path '" + hostPath + "' must be absolute or start with $HOME";

  // absolute: must be the home directory itself or live under it
  if (home.empty() || home[0] != '/' || home == "/")
    return "share host path '" + hostPath + "': cannot confine to an unknown home directory";
  std::string h = home;
  while (h.size() > 1 && h.back() == '/') h.pop_back();
  if (hostPath == h) return "";
  if (hostPath.size() > h.size() && hostPath.compare(0, h.size(), h) == 0 && hostPath[h.size()] == '/')
    return "";
  return "a .local override may only share directories under your home ("
         + h + "); '" + hostPath + "' is outside it";
}

bool needsRebuild(long crateMtime, long specMtime, long localMtime) {
  if (crateMtime < 0) return true;
  if (specMtime > crateMtime) return true;
  if (localMtime >= 0 && localMtime > crateMtime) return true;
  return false;
}

} // namespace ProfilePure
