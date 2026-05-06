// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "auto_fw_pure.h"

#include <sstream>

namespace AutoFwPure {

namespace {

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

} // anon

std::string validateExternalIface(const std::string &iface) {
  if (iface.empty()) return "external interface is empty";
  if (iface.size() > 15) return "external interface name longer than 15 chars (FreeBSD IFNAMSIZ)";
  for (char c : iface) {
    bool ok = isAlnum(c) || c == '.' || c == '_';
    if (!ok)
      return "external interface contains invalid character '" + std::string(1, c) + "'";
  }
  return "";
}

std::string validateRuleAddress(const std::string &addr) {
  if (addr.empty()) return "rule address is empty";
  if (addr.size() > 18) return "rule address longer than 18 chars (max '255.255.255.255/32')";
  bool sawSlash = false;
  for (char c : addr) {
    if (c == '/') {
      if (sawSlash) return "rule address has more than one '/'";
      sawSlash = true;
      continue;
    }
    bool ok = (c >= '0' && c <= '9') || c == '.';
    if (!ok)
      return "rule address contains invalid character '" + std::string(1, c) + "'";
  }
  return "";
}

std::string formatSnatRule(const std::string &externalIface,
                           const std::string &jailAddr) {
  std::ostringstream o;
  o << "nat on " << externalIface
    << " inet from " << jailAddr
    << " to ! " << jailAddr
    << " -> (" << externalIface << ")";
  return o.str();
}

std::string formatSnatAnchorLine(const std::string &externalIface,
                                 const std::string &jailAddr) {
  return formatSnatRule(externalIface, jailAddr) + "\n";
}

} // namespace AutoFwPure
