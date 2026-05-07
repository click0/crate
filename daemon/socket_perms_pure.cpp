// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "socket_perms_pure.h"

#include <cctype>
#include <string>

namespace SocketPermsPure {

namespace {

bool allOctal(const std::string &s) {
  if (s.empty()) return false;
  for (char c : s)
    if (c < '0' || c > '7') return false;
  return true;
}

bool isAlnumDashUnderscore(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

std::string validateName(const std::string &s, const char *what) {
  if (s.empty()) return "";  // empty = "leave alone", caller handles
  if (s.size() > 32)
    return std::string(what) + " too long (>32 chars): '" + s + "'";
  if (s[0] == '-')
    return std::string(what) + " must not start with '-': '" + s + "'";
  for (char c : s)
    if (!isAlnumDashUnderscore(c))
      return std::string(what) + " contains forbidden char (allowed: [A-Za-z0-9_-]): '" + s + "'";
  return "";
}

} // anon

std::string parseUnixModeStr(const std::string &s, unsigned *out) {
  if (out == nullptr) return "internal: parseUnixModeStr called with null out";
  if (s.empty())      return "mode is empty";

  std::string body = s;
  // Accept "0o660" (Python/YAML 1.2 octal) by stripping the prefix.
  if (body.size() >= 2 && body[0] == '0' && (body[1] == 'o' || body[1] == 'O'))
    body = body.substr(2);
  // "0660" is identical to "660" in chmod(1) semantics — both are
  // octal. Strip a single leading zero (but not multiple — "00660"
  // is still rejected because no chmod source produces that).
  if (body.size() >= 2 && body[0] == '0' && body[1] != '0')
    body = body.substr(1);

  if (body.size() > 4)
    return "mode '" + s + "' has too many octal digits (max 4)";
  if (!allOctal(body))
    return "mode '" + s + "' contains non-octal digits (only 0..7 allowed)";

  unsigned v = 0;
  for (char c : body) v = v * 8 + (c - '0');
  if (v > 07777)
    return "mode '" + s + "' out of range (max 07777)";
  *out = v;
  return "";
}

std::string validateUserName(const std::string &s)  { return validateName(s, "user name"); }
std::string validateGroupName(const std::string &s) { return validateName(s, "group name"); }

std::string validateUnixSocketPerms(const std::string &owner,
                                    const std::string &group,
                                    unsigned mode) {
  if (auto e = validateUserName(owner);  !e.empty()) return e;
  if (auto e = validateGroupName(group); !e.empty()) return e;
  if (mode > 07777)
    return "mode out of range (max 07777): " + std::to_string(mode);
  return "";
}

bool isModeTight(unsigned mode) {
  // 0660 = group-writable, world-disallowed. Anything stricter
  // (0600, 0640) also passes. Anything looser (0666, 0666 + sticky,
  // world-readable) does not.
  return (mode & 07777) <= 0660u && (mode & 07) == 0u;
}

} // namespace SocketPermsPure
