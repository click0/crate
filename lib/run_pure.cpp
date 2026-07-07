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
  if (user.empty()) return "";  // unchanged: caller's default handling
  if (user.size() > 32) return "cron user is longer than 32 chars";
  if (user.front() == '-') return "cron user must not start with '-'";
  for (char c : user) {
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9') || c == '_' || c == '-';
    if (!ok)
      return "cron user contains an invalid character "
             "(allowed: [A-Za-z0-9_-])";
  }
  return "";
}

}
