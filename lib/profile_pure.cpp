// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "profile_pure.h"
#include "warm_pure.h"

#include <sstream>

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

// 1.1.71: key PATHS, in the parser's '_' spelling. Until 1.1.70 these
// were compared as exact top-level strings, so `security-advanced` /
// `socket-proxy` (the parser takes both spellings) passed, the listed
// `securelevel` was no key at all (the real one is security/securelevel),
// and devices / ipc/raw_sockets / zfs/datasets were not listed. A new
// security/ or ipc/ key that loosens the jail has to be added here.
const std::vector<std::string> &forbiddenLocalKeys() {
  static const std::vector<std::string> keys = {
    "security_advanced",   // MAC / capsicum / sysctl hardening chosen by the profile
    "dbus",                // D-Bus policy: a filter is only as strict as its loosest rule
    "base",                // host-ro / host-dirs: mounts host directories into the jail
    "scripts",             // shell run as root in the create chroot and at run time
    "encrypted",           // turning encryption off or weakening the cipher
    "socket_proxy",        // exposes host unix sockets (same class as shares outside $HOME)
    "devices",             // all / input / usb / gpu: host device nodes in the jail's /dev
    "security/securelevel",        // lowering it
    "security/enforce_statfs",     // seeing the host's mounts
    "security/allow_quotas",       // the allow.* flags of jail(8)
    "security/allow_set_hostname",
    "security/allow_chflags",
    "security/allow_mlock",
    "security/children_max",       // nested jails
    "ipc/raw_sockets",             // raw sockets: spoofing, sniffing
    "ipc/sysvipc",                 // the host's System V IPC objects
    "zfs/datasets",                // host datasets attached to the jail
  };
  return keys;
}

std::string normaliseKey(const std::string &key) {
  std::string k = key;
  for (auto &c : k)
    if (c == '-') c = '_';
  return k;
}

std::string checkLocalKeyPath(const std::vector<std::string> &path) {
  std::string joined;
  for (auto &p : path) {
    if (!joined.empty()) joined += '/';
    joined += normaliseKey(p);
  }
  for (auto &k : forbiddenLocalKeys())
    if (k == joined)
      return "a .local override may not set '" + joined + "' (it could loosen the profile's "
             "isolation); put it in a copy of the profile under ~/.config/crate/profiles/ instead";
  return "";
}

std::string checkLocalTopLevelKey(const std::string &key) {
  return checkLocalKeyPath({key});
}

std::string checkLocalDuplicateKeys(const std::vector<std::string> &keys, const std::string &where) {
  for (size_t i = 0; i < keys.size(); i++)
    for (size_t j = i + 1; j < keys.size(); j++)
      if (normaliseKey(keys[i]) == normaliseKey(keys[j]))
        return "a .local override names '" + (where.empty() ? std::string() : where + "/")
               + keys[j] + "' twice" + (keys[i] != keys[j] ? " (as '" + keys[i] + "' too)" : "")
               + "; only one of them would be checked";
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

std::string cacheKeyPath(const std::string &home, const std::string &name) {
  return buildDir(home) + "/" + name + ".key";
}

// Length-prefixed, so no value can imitate another field.
std::string cacheKeyInput(const std::string &mergedSpec,
                          const std::map<std::string, std::string> &vars,
                          const std::string &version) {
  std::ostringstream s;
  s << "crate-profile-cache 1\n"
    << "version " << version.size() << ':' << version << '\n';
  for (auto &kv : vars)
    s << "var " << kv.first.size() << ':' << kv.first << ' '
      << kv.second.size() << ':' << kv.second << '\n';
  s << "spec " << mergedSpec.size() << ':' << mergedSpec;
  return s.str();
}

CacheAction cacheAction(long long crateMtimeNs, long long mergedMtimeNs,
                        const std::string &storedKey, const std::string &key) {
  if (key.empty() || storedKey != key || mergedMtimeNs < 0) return CacheAction::RewriteAndBuild;
  if (crateMtimeNs < 0 || crateMtimeNs <= mergedMtimeNs) return CacheAction::Build;
  return CacheAction::UpToDate;
}

} // namespace ProfilePure
