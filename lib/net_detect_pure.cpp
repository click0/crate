// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "net_detect_pure.h"

#include <sstream>

namespace NetDetectPure {

namespace {

// Trim leading + trailing ASCII whitespace.
std::string trim(const std::string &s) {
  std::size_t a = 0, b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
  while (b > a && (s[b-1] == ' ' || s[b-1] == '\t' || s[b-1] == '\r' || s[b-1] == '\n')) b--;
  return s.substr(a, b - a);
}

bool isInterfaceTokenSafe(const std::string &name) {
  // FreeBSD interface names: alnum + . (vlan tag) + _, length 1..15.
  // Same shape as AutoFwPure::validateExternalIface so the result
  // round-trips into auto-fw without surprise.
  if (name.empty() || name.size() > 15) return false;
  for (char c : name) {
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9') || c == '.' || c == '_';
    if (!ok) return false;
  }
  return true;
}

} // anon

std::string parseRouteOutput(const std::string &out) {
  std::istringstream is(out);
  std::string line;
  while (std::getline(is, line)) {
    auto trimmed = trim(line);
    // Match "interface:" (case-sensitive — route(8) is consistent).
    static const char kKey[] = "interface:";
    const std::size_t kKeyLen = sizeof(kKey) - 1;
    if (trimmed.size() < kKeyLen) continue;
    if (trimmed.compare(0, kKeyLen, kKey) != 0) continue;
    auto value = trim(trimmed.substr(kKeyLen));
    if (!isInterfaceTokenSafe(value)) {
      // Garbage after the colon — don't accept; return empty so the
      // caller treats it as "not detected".
      return "";
    }
    return value;
  }
  return "";
}

} // namespace NetDetectPure
