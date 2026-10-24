// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "run_pure.h"
#include "util.h"   // Util::shellQuote, Util::toUInt, Util::filePathToBareName
#include "name_limits.h"
#include "warm_pure.h"

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

}
