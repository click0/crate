// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "run_pure.h"
#include "runtime_paths_pure.h"   // 1.1.70: containerNameOfJail
#include "util.h"   // Util::shellQuote, Util::toUInt, Util::filePathToBareName
#include "name_limits.h"
#include "warm_pure.h"

#include <cctype>
#include <cstdlib>
#include <sstream>
#include <string>

namespace RunPure {

std::string argsToString(int argc, char **argv) {
  std::ostringstream ss;
  for (int i = 0; i < argc; i++)
    ss << " " << Util::shellQuote(argv[i]);
  return ss.str();
}

unsigned envOrDefault(const char *name, unsigned def) {
  auto *val = ::getenv(name);
  if (!val) return def;
  try { return Util::toUInt(val); } catch (...) { return def; }
}

std::string validateCronUser(const std::string &user) {
  // 1.1.27: empty is now rejected here — the 1.1.22 version waved it
  // through claiming "caller's default handling", but no such handling
  // existed: the "root" default lives in the Spec struct initializer,
  // so an explicit `user: ""` reached `/var/cron/tabs/` (a directory).
  // run.cpp now maps empty → "root" BEFORE validating.
  if (user.empty()) return "cron user is empty";
  if (user.size() > 32) return "cron user is longer than 32 chars";
  if (user.front() == '-') return "cron user must not start with '-'";
  if (user == "." || user == "..") return "cron user is reserved";
  for (char c : user) {
    // 1.1.27: '.' is allowed — FreeBSD pw(8) accepts it in login names
    // (`john.doe` is common on first.last hosts) and 1.1.22 wrongly
    // rejected such specs. It is shell-inert and, with '/' excluded and
    // "."/".." reserved above, cannot traverse.
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
    if (!ok)
      return "cron user contains an invalid character "
             "(allowed: [A-Za-z0-9._-])";
  }
  return "";
}

std::string validateCrateFileJailName(const std::string &crateFile) {
  auto name = Util::filePathToBareName(crateFile);
  if (auto e = WarmPure::validateJailName(name); !e.empty())
    return "the jail is named after the .crate file name '" + name + "': "
           + e + " — rename the file to use only [A-Za-z0-9._-] (max "
           + std::to_string(NameLimits::kJailName) + " chars) before the "
           "first '.', or run it with --warm-base/--name";
  return "";
}

std::string jailXnamePidSuffix(long pid) {
  return "_pid" + std::to_string(pid);
}

bool jailXnameHasPid(const std::string &jailName, long pid) {
  const std::string suffix = jailXnamePidSuffix(pid);
  if (jailName.size() <= suffix.size()) return false;   // needs a non-empty <name>
  return jailName.compare(jailName.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string containerNameOf(const std::string &jailName) {
  static const std::string kTag = "_pid";
  const size_t at = jailName.rfind(kTag);
  if (at == std::string::npos || at == 0) return jailName;
  const size_t digits = at + kTag.size();
  if (digits >= jailName.size()) return jailName;
  for (size_t i = digits; i < jailName.size(); i++)
    if (jailName[i] < '0' || jailName[i] > '9') return jailName;
  return jailName.substr(0, at);
}

bool jailXnamePid(const std::string &jailName, long &pidOut) {
  const std::string base = containerNameOf(jailName);
  if (base == jailName) return false;   // no well-formed _pid<digits>
  const std::string digits = jailName.substr(base.size() + 4);
  if (digits.empty() || digits.size() > 9) return false;
  pidOut = std::stol(digits);
  return pidOut > 0;
}

std::string netgraphBridgeNodeName(int jid, unsigned seq) {
  return "crate_br_" + std::to_string(jid < 0 ? 0 : jid) + "_" + std::to_string(seq);
}

std::string ngctlShowName(const std::string &out) {
  const auto pos = out.find("Name: ");
  if (pos == std::string::npos) return "";
  size_t b = pos + 6;
  while (b < out.size() && out[b] == ' ') b++;
  size_t e = b;
  while (e < out.size() && !std::isspace((unsigned char)out[e])) e++;
  const std::string name = out.substr(b, e - b);
  if (name.empty() || name == "<unnamed>") return "";
  for (char c : name)
    if (!std::isalnum((unsigned char)c) && c != '_' && c != '-') return "";
  return name;
}

std::string containerNameOfJail(const std::string &jailName, const std::string &jailPath) {
  const std::string byName = containerNameOf(jailName);
  if (byName != jailName) return byName;
  // "jail-<name>-<hex>": `crate run` appends Util::randomHex(4), 8 hex digits
  const std::string dir = RuntimePathsPure::crateJailDirName(jailPath);
  const size_t kHex = 8;
  if (dir.size() > 5 + 1 + kHex && dir[dir.size() - kHex - 1] == '-') {
    bool hex = true;
    for (size_t i = dir.size() - kHex; i < dir.size(); i++)
      if (!std::isxdigit((unsigned char)dir[i])) { hex = false; break; }
    if (hex) return dir.substr(5, dir.size() - 5 - kHex - 1);
  }
  return jailName;
}

ContainerChoice chooseContainer(const std::vector<JailRef> &jails, const std::string &target,
                                uint32_t callerUid, bool anyOwner) {
  ContainerChoice c;
  if (target.empty()) return c;
  // 1. the exact kernel name
  for (size_t i = 0; i < jails.size(); i++) {
    const auto &j = jails[i];
    if (j.name == target && RuntimePathsPure::isCrateJailPath(j.path)) {
      c.index = (int)i;
      c.matches = 1;
      return c;
    }
  }
  // 2. the container name, among the caller's own running jails (every
  //    tenant's with anyOwner)
  std::vector<size_t> byName;
  for (size_t i = 0; i < jails.size(); i++) {
    const auto &j = jails[i];
    if (j.dying || !RuntimePathsPure::isCrateJailPath(j.path)) continue;
    if (!anyOwner && RuntimePathsPure::crateJailOwnerUid(j.path) != (int64_t)callerUid) continue;
    if (containerNameOfJail(j.name, j.path) == target) byName.push_back(i);
  }
  // 3. the jid
  int byJid = -1;
  if (target.size() <= 9 && target.find_first_not_of("0123456789") == std::string::npos) {
    const int jid = std::stoi(target);
    for (size_t i = 0; i < jails.size(); i++)
      if (jails[i].jid == jid && RuntimePathsPure::isCrateJailPath(jails[i].path)) {
        byJid = (int)i;
        break;
      }
  }
  if (byJid >= 0) {
    if (byName.empty() || (byName.size() == 1 && (int)byName[0] == byJid)) {
      c.index = byJid;
      c.matches = 1;
      return c;
    }
    c.matches = (unsigned)byName.size() + 1;   // "3": jid 3 and container "3"
    return c;
  }
  c.matches = (unsigned)byName.size();
  if (byName.size() == 1) c.index = (int)byName[0];
  return c;
}

bool epairUnit(const std::string &ifname, unsigned &unitOut) {
  static const std::string kPrefix = "epair";
  if (ifname.size() < kPrefix.size() + 2) return false;
  if (ifname.compare(0, kPrefix.size(), kPrefix) != 0) return false;
  const char half = ifname.back();
  if (half != 'a' && half != 'b') return false;
  const std::string digits = ifname.substr(kPrefix.size(), ifname.size() - kPrefix.size() - 1);
  if (digits.empty() || digits.size() > 9) return false;
  unsigned v = 0;
  for (char c : digits) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + (unsigned)(c - '0');
  }
  unitOut = v;
  return true;
}

RunUser effectiveRunUser(const std::string &specUser, const std::string &operatorName,
                         unsigned operatorUid) {
  RunUser u;
  if (specUser == "root") { u.name = "root"; u.root = true; return u; }
  if (!specUser.empty()) {
    u.name = specUser;
    if (specUser == operatorName && operatorUid != 0) u.mirrored = true;
    return u;
  }
  if (operatorUid == 0 || operatorName == "root" || operatorName.empty()) {
    u.name = kDedicatedRunUser;
    u.dedicated = true;
    return u;
  }
  u.name = operatorName;
  u.mirrored = true;
  return u;
}

bool runUserNeedsAccount(const RunUser &u) {
  return !u.root && !u.mirrored;
}

std::string runUserCookieHome(const RunUser &u, const std::string &pwHome) {
  if (u.root || u.mirrored) return "";
  std::string h = pwHome;
  while (h.size() > 1 && h.back() == '/') h.pop_back();
  if (h.empty() || h[0] != '/' || h == "/" || h == "/root") return "";
  if (h.find("/../") != std::string::npos
      || (h.size() >= 3 && h.compare(h.size() - 3, 3, "/..") == 0))
    return "";
  return h;
}

std::string validateRunUser(const std::string &user) {
  if (user.empty() || user == "root") return "";
  if (user.size() > 32) return "run/user: name longer than 32 chars";
  char c0 = user[0];
  bool alpha0 = (c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') || c0 == '_';
  if (!alpha0) return "run/user: name must start with a letter or '_'";
  for (char c : user) {
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
           || c == '.' || c == '_' || c == '-';
    if (!ok) return std::string("run/user: invalid character '") + c + "' in name (allowed: [A-Za-z0-9._-])";
  }
  return "";
}

std::string epairIp6(unsigned num, unsigned idx) {
  // 4 addresses per pair: [base+0 .. base+3] is one /126; host gets
  // +1, jail +2 (+0 is the network address, +3 stays free).
  const unsigned long long offset = 0x100ull + 4ull * num + 1ull + (idx ? 1ull : 0ull);
  std::ostringstream ss;
  ss << "fd00:cra7:e::";
  if (offset > 0xffffull)
    ss << std::hex << (offset >> 16) << ":" << std::hex << (offset & 0xffffull);
  else
    ss << std::hex << offset;
  return ss.str();
}

std::string parseRunTimeout(const std::string &text, unsigned &secondsOut) {
  if (text.empty()) return "run/timeout: empty value (omit the key for no timeout)";
  size_t n = 0;
  while (n < text.size() && text[n] >= '0' && text[n] <= '9') n++;
  if (n == 0) return "run/timeout: '" + text + "' must be a number of seconds, optionally with s/m/h";
  if (n > 9) return "run/timeout: '" + text + "' is out of range";
  unsigned long long v = std::strtoull(text.substr(0, n).c_str(), nullptr, 10);
  std::string unit = text.substr(n);
  unsigned long long mult = 1;
  if (unit.empty() || unit == "s") mult = 1;
  else if (unit == "m") mult = 60;
  else if (unit == "h") mult = 3600;
  else return "run/timeout: unknown unit '" + unit + "' in '" + text + "' (s, m or h)";
  v *= mult;
  if (v == 0) return "run/timeout: 0 means no timeout — omit the key instead";
  if (v > kRunTimeoutMax) return "run/timeout: '" + text + "' exceeds the 30-day maximum";
  secondsOut = (unsigned)v;
  return "";
}

std::vector<std::string> runTimeoutPrefix(unsigned seconds) {
  if (seconds == 0) return {};
  return {"/usr/bin/timeout", "-k", std::to_string(kRunTimeoutKillAfter), std::to_string(seconds)};
}

bool runTimedOut(unsigned seconds, int exitCode) {
  return seconds > 0 && exitCode == kRunTimeoutExitCode;
}

}
