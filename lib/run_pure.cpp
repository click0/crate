// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "run_pure.h"
#include "util.h"   // Util::shellQuote, Util::toUInt

#include <cstdlib>
#include <sstream>

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

}
