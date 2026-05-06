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

// --- ipfw alternative backend ---

namespace {

// Reserved high-number ranges (matches throttle's 10000/20000 bases).
constexpr unsigned kIpfwNatBase  = 30000;
constexpr unsigned kIpfwRuleBase = 40000;
constexpr unsigned kIpfwIdMax    = 65535;  // ipfw rule numbers are 16-bit

} // anon

unsigned natIdForJail(int jid) {
  // Cast through unsigned so a negative jid (which shouldn't happen
  // in practice) doesn't underflow the base.
  unsigned u = static_cast<unsigned>(jid);
  return kIpfwNatBase + u;
}

unsigned ruleIdForJail(int jid) {
  unsigned u = static_cast<unsigned>(jid);
  return kIpfwRuleBase + u;
}

std::string validateIpfwNatId(unsigned id) {
  if (id < kIpfwNatBase) return "ipfw NAT id below 30000 reserved range";
  if (id > kIpfwIdMax)   return "ipfw NAT id exceeds 16-bit max";
  return "";
}

std::vector<std::string> buildIpfwNatConfigArgv(unsigned natId,
                                                const std::string &externalIface) {
  return {"/sbin/ipfw", "nat", std::to_string(natId),
          "config", "if", externalIface};
}

std::vector<std::string> buildIpfwNatConfigWithRedirsArgv(
    unsigned natId,
    const std::string &externalIface,
    const std::vector<RedirPort> &redirs) {
  auto argv = buildIpfwNatConfigArgv(natId, externalIface);
  for (const auto &r : redirs) {
    // ipfw redir_port format:
    //   redir_port <proto> <jailIp>:<jailLo>[-<jailHi>] <hostLo>[-<hostHi>]
    argv.push_back("redir_port");
    argv.push_back(r.proto);
    std::string jailPortToken =
      (r.jailPortLo == r.jailPortHi)
        ? std::to_string(r.jailPortLo)
        : (std::to_string(r.jailPortLo) + "-" + std::to_string(r.jailPortHi));
    argv.push_back(r.jailAddr + ":" + jailPortToken);
    std::string hostPortToken =
      (r.hostPortLo == r.hostPortHi)
        ? std::to_string(r.hostPortLo)
        : (std::to_string(r.hostPortLo) + "-" + std::to_string(r.hostPortHi));
    argv.push_back(hostPortToken);
  }
  return argv;
}

std::vector<std::string> buildIpfwNatRuleArgv(unsigned ruleId,
                                              unsigned natId,
                                              const std::string &jailAddr,
                                              const std::string &externalIface) {
  return {"/sbin/ipfw", "add", std::to_string(ruleId),
          "nat", std::to_string(natId),
          "ip", "from", jailAddr, "to", "any",
          "out", "via", externalIface};
}

std::vector<std::string> buildIpfwRuleDeleteArgv(unsigned ruleId) {
  return {"/sbin/ipfw", "delete", std::to_string(ruleId)};
}

std::vector<std::string> buildIpfwNatDeleteArgv(unsigned natId) {
  return {"/sbin/ipfw", "nat", std::to_string(natId), "delete"};
}

} // namespace AutoFwPure
