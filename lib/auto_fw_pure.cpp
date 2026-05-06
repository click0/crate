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

// --- Port-forward (rdr) ---

std::string validateProto(const std::string &proto) {
  if (proto.empty()) return "proto is empty";
  if (proto != "tcp" && proto != "udp")
    return "proto must be 'tcp' or 'udp', got '" + proto + "'";
  return "";
}

std::string validatePort(unsigned port) {
  if (port == 0)     return "port 0 is invalid";
  if (port > 65535)  return "port " + std::to_string(port) + " > 65535";
  return "";
}

namespace {

std::string formatPortToken(unsigned lo, unsigned hi) {
  if (lo == hi) return std::to_string(lo);
  std::ostringstream o;
  o << lo << ":" << hi;
  return o.str();
}

} // anon

std::string formatRdrRule(const std::string &externalIface,
                          const std::string &proto,
                          unsigned hostPortLo, unsigned hostPortHi,
                          const std::string &jailAddr,
                          unsigned jailPortLo, unsigned jailPortHi) {
  std::ostringstream o;
  o << "rdr on " << externalIface
    << " inet proto " << proto
    << " from any to (" << externalIface << ")"
    << " port " << formatPortToken(hostPortLo, hostPortHi)
    << " -> " << jailAddr
    << " port " << formatPortToken(jailPortLo, jailPortHi);
  return o.str();
}

std::string formatRdrAnchorLine(const std::string &externalIface,
                                const std::string &proto,
                                unsigned hostPortLo, unsigned hostPortHi,
                                const std::string &jailAddr,
                                unsigned jailPortLo, unsigned jailPortHi) {
  return formatRdrRule(externalIface, proto, hostPortLo, hostPortHi,
                       jailAddr, jailPortLo, jailPortHi) + "\n";
}

} // namespace AutoFwPure
